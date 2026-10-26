import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// An HTTP request made by PerfectOAuth2. Its description and mirror hide the body and the
/// `Authorization` header.
public struct OAuth2HTTPRequest: Sendable, CustomStringConvertible, CustomReflectable {
    public enum Method: String, Sendable { case get = "GET", post = "POST" }

    public var method: Method
    public var url: URL
    public var headers: [String: String]
    public var body: Data?

    public init(method: Method, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }

    public var description: String {
        "\(method.rawValue) \(url.scheme ?? "")://\(url.host ?? "")\(url.path) (headers and body redacted)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "method": method.rawValue,
            "url": "\(url.scheme ?? "")://\(url.host ?? "")\(url.path)",
            "headers": headers.keys.sorted().map { "\($0): <redacted>" },
            "body": body == nil ? "nil" : "<redacted \(body?.count ?? 0) bytes>",
        ], displayStyle: .struct)
    }
}

public struct OAuth2HTTPResponse: Sendable {
    public var status: Int
    public var body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

/// Sends PerfectOAuth2's HTTP requests. The default is `NIOTransport`; `URLSessionTransport` is an
/// opt-in, and you can supply your own through `OAuth2HTTPOptions.transport`.
///
/// Implementations should not follow redirects, should enforce a deadline, and should stop reading
/// a body past a size limit, throwing the matching `OAuth2Error`s.
public protocol OAuth2Transport: Sendable {
    func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse
}

/// An opt-in transport on Foundation's URLSession, one ephemeral session per request. Use it when you
/// need system proxy settings, which `NIOTransport` (the default) ignores.
///
/// **Not memory- or traffic-bounded on Linux**, especially with Swift 6.2: after a capped or timed-out
/// request is cancelled, corelibs Foundation keeps reading and discarding the rest of the body in the
/// background (see the README for measurements). On macOS it is bounded, given the gzip refusal below.
///
/// - No cookies, cache or credential storage.
/// - Redirects are not followed: the 3xx comes back as `OAuth2Error.httpStatus`.
/// - `timeout` is a deadline for the whole request, not just the gap between bytes.
/// - `Accept-Encoding: identity` is sent and any other `Content-Encoding` is refused before the body
///   is read (Darwin would otherwise decompress before the size check).
/// - A `Content-Length` over `maximumResponseBytes` is refused before the body is read; otherwise the
///   call returns as soon as the received body passes the limit and the task is cancelled. On Darwin
///   that stops the download. On Linux, corelibs Foundation keeps reading and discarding in the
///   background after cancellation, badly so on Swift 6.2 (see the README's "Response limits on
///   Linux"). Only a custom `OAuth2Transport` gives hard memory and traffic bounds.
public struct URLSessionTransport: OAuth2Transport {
    public let timeout: TimeInterval
    public let maximumResponseBytes: Int

    /// `timeout` is clamped to 1 ms ... 1 day: corelibs URLSession traps on an infinite timeout.
    public init(timeout: TimeInterval = 30, maximumResponseBytes: Int = 1 << 20) {
        self.timeout = timeout.isNaN ? 0.001 : min(max(timeout, 0.001), 86_400)
        self.maximumResponseBytes = max(0, maximumResponseBytes)
    }

    public func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        urlRequest.httpBody = request.body
        urlRequest.timeoutInterval = timeout
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        // Darwin decompresses gzip/deflate/br before the delegate sees the bytes, so a compressed body
        // would get round the size cap as a memory bound. Ask for identity, and refuse anything else.
        urlRequest.setValue("identity", forHTTPHeaderField: "Accept-Encoding")

        let delegate = CappedDataDelegate(limit: maximumResponseBytes)
        // Neither the deadline nor the session setup runs on Swift's cooperative pool. On Linux,
        // corelibs' URLSession creation, resume() and cancel() can block for a long time while it
        // drains earlier cancelled transfers; on the cooperative pool that starved the deadline
        // itself (a 5 s timeout fired after 75 s on Swift 6.2). A Dispatch timer and a Dispatch
        // thread for setup keep the caller's deadline honest.
        let seconds = timeout  // clamped in init
        let deadline = DispatchWorkItem { delegate.fail(.timedOut) }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: deadline)
        defer {
            deadline.cancel()
            delegate.invalidate()
        }

        try Task.checkCancellation()
        let timeout = self.timeout
        let finalRequest = urlRequest
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<OAuth2HTTPResponse, any Error>) in
                // Not started if already cancelled or timed out: no request goes out.
                guard delegate.start(continuation) else { return }
                DispatchQueue.global().async {
                    let configuration = URLSessionConfiguration.ephemeral
                    configuration.timeoutIntervalForRequest = timeout
                    configuration.timeoutIntervalForResource = timeout
                    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
                    configuration.urlCache = nil
                    configuration.httpCookieStorage = nil
                    configuration.httpShouldSetCookies = false
                    configuration.urlCredentialStorage = nil
                    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
                    let task = session.dataTask(with: finalRequest)
                    if delegate.attach(session: session, task: task) {
                        task.resume()
                    } else {
                        session.invalidateAndCancel()  // finished (timed out or cancelled) during setup
                    }
                }
            }
        } onCancel: {
            delegate.fail(.network("cancelled"))
        }
    }
}

private func cancelOffThread(_ task: URLSessionTask) {
    DispatchQueue.global().async { task.cancel() }
}

/// Collects one task's response, enforcing the size limit, and resumes the continuation once.
private final class CappedDataDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    // All mutable state is guarded by `lock`.
    private let lock = NSLock()
    private let limit: Int
    private var continuation: CheckedContinuation<OAuth2HTTPResponse, any Error>?
    private var pendingFailure: OAuth2Error?
    private var finished = false
    private var status = 0
    private var data = Data()
    private var _task: URLSessionTask?
    private var session: URLSession?
    private var invalidated = false

    init(limit: Int) { self.limit = limit }

    /// Records the session and task; returns false if the request already finished or the caller
    /// has returned, in which case the task must not be resumed.
    func attach(session: URLSession, task: URLSessionTask) -> Bool {
        lock.withLock {
            guard !finished, !invalidated else { return false }
            self.session = session
            _task = task
            return true
        }
    }

    /// Called when the caller returns: invalidates the session off the calling thread (or makes a
    /// later `attach` refuse, if setup hasn't finished).
    func invalidate() {
        let session: URLSession? = lock.withLock {
            invalidated = true
            defer { self.session = nil }
            return self.session
        }
        if let session { DispatchQueue.global().async { session.invalidateAndCancel() } }
    }

    /// Stores the continuation; returns false (after resuming it with the failure) if the request
    /// already failed (cancelled or timed out) and shouldn't start.
    func start(_ continuation: CheckedContinuation<OAuth2HTTPResponse, any Error>) -> Bool {
        let failure: OAuth2Error? = lock.withLock {
            if let pendingFailure, !finished {
                finished = true
                return pendingFailure
            }
            self.continuation = continuation
            return nil
        }
        if let failure {
            continuation.resume(throwing: failure)
            return false
        }
        return true
    }

    /// Ends the request with `error` (timeout, cancellation, size limit) unless it already finished.
    func fail(_ error: OAuth2Error) {
        let (continuation, task): (CheckedContinuation<OAuth2HTTPResponse, any Error>?, URLSessionTask?) = lock.withLock {
            guard !finished else { return (nil, nil) }
            guard let continuation = self.continuation else {
                pendingFailure = pendingFailure ?? error
                return (nil, _task)
            }
            finished = true
            self.continuation = nil
            data = Data()
            return (continuation, _task)
        }
        // Resume first: on Linux, corelibs' cancel() can block for as long as the session's queue is
        // busy reading, which would hold the caller (and the deadline) hostage.
        continuation?.resume(throwing: error)
        if let task { cancelOffThread(task) }
    }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        if response.expectedContentLength > Int64(limit) {
            fail(.responseTooLarge(limit: limit))
            completionHandler(.cancel)
            return
        }
        if let encoding = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Encoding")?
            .trimmingCharacters(in: .whitespaces).lowercased(), !encoding.isEmpty, encoding != "identity" {
            fail(.invalidResponse("compressed response refused (Content-Encoding: \(encoding.prefix(32)))"))
            completionHandler(.cancel)
            return
        }
        lock.withLock { status = (response as? HTTPURLResponse)?.statusCode ?? 0 }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        let tooLarge: Bool = lock.withLock {
            guard !finished else { return false }
            if data.count + chunk.count > limit { return true }
            data.append(chunk)
            return false
        }
        if tooLarge { fail(.responseTooLarge(limit: limit)) }
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)  // never follow: a redirected POST could carry the client secret elsewhere
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let outcome: (CheckedContinuation<OAuth2HTTPResponse, any Error>, Result<OAuth2HTTPResponse, OAuth2Error>)? = lock.withLock {
            guard !finished, let continuation else {
                if !finished, continuation == nil {
                    pendingFailure = pendingFailure ?? Self.map(error) ?? .network("finished before start")
                }
                return nil
            }
            finished = true
            self.continuation = nil
            if let mapped = Self.map(error) {
                return (continuation, .failure(mapped))
            }
            let response = OAuth2HTTPResponse(status: status, body: data)
            data = Data()
            return (continuation, .success(response))
        }
        if let (continuation, result) = outcome { continuation.resume(with: result) }
    }

    private static func map(_ error: (any Error)?) -> OAuth2Error? {
        guard let error else { return nil }
        if let urlError = error as? URLError {
            if urlError.code == .timedOut { return .timedOut }
            return .network("URLError \(urlError.code.rawValue)")
        }
        return .network(String(describing: type(of: error)))
    }
}
