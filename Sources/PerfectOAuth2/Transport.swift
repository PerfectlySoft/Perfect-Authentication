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

/// Sends PerfectOAuth2's HTTP requests. The default is `URLSessionTransport`; supply your own (for
/// example one on AsyncHTTPClient) through `OAuth2HTTPOptions.transport`.
///
/// Implementations should not follow redirects, should enforce a deadline, and should stop reading
/// a body past a size limit, throwing the matching `OAuth2Error`s.
public protocol OAuth2Transport: Sendable {
    func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse
}

/// The default transport: Foundation's URLSession, one ephemeral session per request.
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

    public init(timeout: TimeInterval = 30, maximumResponseBytes: Int = 1 << 20) {
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
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

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil

        let delegate = CappedDataDelegate(limit: maximumResponseBytes)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        let task = session.dataTask(with: urlRequest)
        delegate.task = task

        let deadline = Task { [timeout] in
            // Clamped: UInt64(.infinity) or a huge value would trap.
            let seconds = timeout.isNaN ? 0 : min(max(timeout, 0), 31_536_000)
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            delegate.fail(.timedOut)
        }
        defer {
            deadline.cancel()
            // Off the cooperative pool for the same reason as `cancelOffThread`.
            DispatchQueue.global().async { session.invalidateAndCancel() }
        }

        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<OAuth2HTTPResponse, any Error>) in
                // Not resumed if already cancelled or timed out: no request goes out.
                if delegate.start(continuation) { task.resume() }
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

    init(limit: Int) { self.limit = limit }

    var task: URLSessionTask? {
        get { lock.withLock { _task } }
        set { lock.withLock { _task = newValue } }
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
