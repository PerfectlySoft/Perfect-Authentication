import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS

/// The default transport: a small HTTP/1.1 client on SwiftNIO, one connection per request.
///
/// It exists because Foundation's URLSession can't be held to a size or time bound on Linux:
/// corelibs keeps reading a cancelled response in the background (see the README). This client stops
/// reading, and closes the connection, the moment a limit is hit, on every platform.
///
/// - **HTTPS only** (plain HTTP only to `localhost`, `127.0.0.1` and `::1`). Full certificate
///   verification against the system trust store, SNI, and NIOSSL's hostname check. For a host name,
///   the certificate must also carry a matching DNS subjectAltName (exact or a one-label `*.`
///   wildcard): NIOSSL alone accepts an IP-address SAN equal to the dialed address, so an IP-only
///   certificate could stand in for a name.
/// - **Nothing is written** until the TLS handshake and that name check have passed, so a server
///   whose certificate is refused never receives the request (or the client secret in it).
/// - `timeout` bounds the whole request, connect to last byte (`OAuth2Error.timedOut`).
/// - At most `maximumResponseBytes` of body are read, chunked or not; a larger `Content-Length` is
///   refused before the body (`OAuth2Error.responseTooLarge`).
/// - `Accept-Encoding: identity` is sent and any other `Content-Encoding` is refused, as is any
///   `Transfer-Encoding` other than plain `chunked`.
/// - Redirects are never followed; a 3xx comes back as is.
/// - Once a request is done (or capped, or timed out) it stops reading and closes without waiting
///   for the server's TLS close_notify (`tlsConfiguration.shutdownTimeout` is overridden).
/// - **No proxy support:** unlike URLSession it ignores system and environment proxy settings. If
///   you need a proxy, use `URLSessionTransport` or your own `OAuth2Transport`.
public struct NIOTransport: OAuth2Transport, CustomReflectable {
    public let timeout: TimeInterval
    public let maximumResponseBytes: Int
    private let group: any EventLoopGroup
    private let tlsConfiguration: TLSConfiguration
    /// Test hook: where to connect for a host and port instead of resolving the name.
    private let addressOverride: (@Sendable (String, Int) -> SocketAddress?)?

    /// - Parameters:
    ///   - group: the event loops to use. The default, `MultiThreadedEventLoopGroup.singleton`, needs
    ///     no shutdown.
    ///   - tlsConfiguration: replaces the default `.makeClientConfiguration()` (full verification,
    ///     system trust store), e.g. to trust a private CA.
    public init(
        group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = 1 << 20,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration()
    ) {
        self.init(group: group, timeout: timeout, maximumResponseBytes: maximumResponseBytes,
                  tlsConfiguration: tlsConfiguration, addressOverride: nil)
    }

    init(
        group: any EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = 1 << 20,
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration(),
        addressOverride: (@Sendable (String, Int) -> SocketAddress?)?
    ) {
        self.group = group
        self.timeout = timeout.isNaN ? 0 : min(max(timeout, 0), 86_400)
        self.maximumResponseBytes = max(0, maximumResponseBytes)
        self.tlsConfiguration = tlsConfiguration
        self.addressOverride = addressOverride
    }

    /// Doesn't descend into the event-loop group: reflecting live NIO internals from another thread
    /// is a data race (found by ThreadSanitizer through `dump(provider)`).
    public var customMirror: Mirror {
        Mirror(self, children: [
            "timeout": timeout,
            "maximumResponseBytes": maximumResponseBytes,
            "group": String(describing: type(of: group)),
        ], displayStyle: .struct)
    }

    public func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse {
        let url = request.url
        try requireSecure(url, "request URL")
        guard let rawHost = url.host else { throw OAuth2Error.insecureURL("request URL has no host") }
        let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]") ? String(rawHost.dropFirst().dropLast()) : rawHost
        let useTLS = url.scheme?.lowercased() == "https"
        let port = url.port ?? (useTLS ? 443 : 80)
        let isLiteral = (try? SocketAddress(ipAddress: host, port: 0)) != nil
        // The request target, exactly as encoded in the URL. (`url.path` is percent-decoded and drops a
        // trailing slash: `/api/` went out as `/api`, `/%3F/` as `/?`, and `/a%20b` as an invalid
        // request line.)
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw OAuth2Error.invalidConfiguration("unparseable request URL")
        }
        let encodedPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        let target = components.percentEncodedQuery.map { encodedPath + "?" + $0 } ?? encodedPath
        let hostField = (host.contains(":") ? "[\(host)]" : host) + (url.port.map { ":\($0)" } ?? "")

        var headers = HTTPHeaders()
        headers.add(name: "Host", value: hostField)
        for (name, value) in request.headers.sorted(by: { $0.key < $1.key })
        where !["host", "accept-encoding", "connection", "content-length", "transfer-encoding"].contains(name.lowercased()) {
            headers.add(name: name, value: value)
        }
        headers.add(name: "Accept-Encoding", value: "identity")
        headers.add(name: "Connection", value: "close")
        if let body = request.body { headers.add(name: "Content-Length", value: String(body.count)) }
        let head = HTTPRequestHead(
            version: .http1_1, method: request.method == .post ? .POST : .GET, uri: target, headers: headers
        )
        let body = request.body

        // When we close (done, capped, timed out), don't wait for the peer's close_notify: NIOSSL's
        // clean shutdown keeps reading, and discarding, whatever the peer sends for up to
        // `shutdownTimeout` (5 s by default). Against an endless body that was 5 s of full-speed
        // reading per capped call.
        var tls = tlsConfiguration
        tls.shutdownTimeout = .milliseconds(1)
        let sslContext: NIOSSLContext?
        do {
            sslContext = useTLS ? try NIOSSLContext(configuration: tls) : nil
        } catch {
            throw OAuth2Error.invalidConfiguration("TLS configuration: \(type(of: error))")
        }
        let limit = maximumResponseBytes
        let loop = group.next()
        let response = loop.makePromise(of: OAuth2HTTPResponse.self)
        let ready = loop.makePromise(of: Void.self)
        let connected = loop.makePromise(of: (any Channel).self)
        let serverName = isLiteral ? nil : host
        let override = addressOverride?(host, port)
        let seconds = timeout

        // Everything that can end the request early (deadline, caller cancellation) and every stage
        // that could still send something consults this state on the event loop, so once the request
        // is aborted nothing more is written and the channel is closed.
        let state = NIOLoopBoundBox.makeBoxSendingValue(RequestState(), as: RequestState.self, eventLoop: loop)
        let abort: @Sendable (OAuth2Error) -> Void = { error in
            loop.execute {
                if state.value.aborted == nil { state.value.aborted = error }
                connected.fail(error)
                ready.fail(error)
                response.fail(error)
                if let channel = state.value.channel {
                    try? channel.syncOptions?.setOption(.autoRead, value: false)
                    channel.close(promise: nil)
                }
            }
        }
        let deadline = loop.scheduleTask(in: .nanoseconds(Int64(seconds * 1_000_000_000))) { abort(.timedOut) }
        defer {
            deadline.cancel()
            // Every promise is completed on every path (a no-op if it already was).
            connected.fail(OAuth2Error.network("request finished"))
            ready.fail(OAuth2Error.network("request finished"))
            response.fail(OAuth2Error.network("request finished"))
        }

        let bootstrap = ClientBootstrap(group: loop)
            .connectTimeout(.nanoseconds(Int64(seconds * 1_000_000_000)))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let sslContext {
                        let tls = try NIOSSLClientHandler(context: sslContext, serverHostname: serverName)
                        try channel.pipeline.syncOperations.addHandler(tls)
                        try channel.pipeline.syncOperations.addHandler(TLSReadyGate(host: serverName, ready: ready))
                    }
                    try channel.pipeline.syncOperations.addHTTPClientHandlers()
                    try channel.pipeline.syncOperations.addHandler(CappedResponseCollector(limit: limit, promise: response))
                }
            }

        return try await withTaskCancellationHandler {
            // Connect through a promise that an abort can fail, so a deadline or cancellation during
            // a slow connect returns at once. A channel that connects after an abort is closed.
            let connecting = override.map { bootstrap.connect(to: $0) } ?? bootstrap.connect(host: host, port: port)
            connecting.whenComplete { result in
                switch result {
                case .success(let channel):
                    loop.execute {
                        if state.value.aborted != nil {
                            channel.close(promise: nil)
                        } else {
                            state.value.channel = channel
                        }
                        connected.succeed(channel)
                    }
                case .failure(let error):
                    connected.fail(error)
                }
            }
            let channel: any Channel
            do {
                channel = try await connected.futureResult.get()
            } catch {
                throw Self.map(await Self.aborted(state, loop) ?? error)
            }
            do {
                try await loop.submit {
                    if let aborted = state.value.aborted { throw aborted }
                }.get()
                if useTLS {
                    try await ready.futureResult.get()
                }
                // Write only if nothing aborted the request after the handshake. A write the HTTP encoder
                // or header validator refuses is our request's fault, not the server's: report it as
                // such rather than as a malformed response.
                try await loop.submit {
                    if let aborted = state.value.aborted { throw aborted }
                    let written = loop.makePromise(of: Void.self)
                    written.futureResult.whenFailure { error in
                        guard state.value.aborted == nil else { return }
                        let rejected = OAuth2Error.invalidConfiguration("HTTP request rejected (\(type(of: error)))")
                        state.value.aborted = rejected
                        response.fail(rejected)
                        channel.close(promise: nil)
                    }
                    channel.write(HTTPClientRequestPart.head(head), promise: nil)
                    if let body { channel.write(HTTPClientRequestPart.body(.byteBuffer(ByteBuffer(bytes: body))), promise: nil) }
                    channel.writeAndFlush(HTTPClientRequestPart.end(nil), promise: written)
                }.get()
                let result = try await response.futureResult.get()
                channel.close(promise: nil)
                return result
            } catch {
                response.fail(error)
                channel.close(promise: nil)
                throw Self.map(await Self.aborted(state, loop) ?? error)
            }
        } onCancel: {
            abort(.cancelled)
        }
    }

    /// The reason the request was aborted (deadline or cancellation), if it was.
    private static func aborted(_ state: NIOLoopBoundBox<RequestState>, _ loop: any EventLoop) async -> OAuth2Error? {
        try? await loop.submit { state.value.aborted }.get()
    }

    static func map(_ error: any Error) -> OAuth2Error {
        switch error {
        case let error as OAuth2Error: return error
        case let error as CertificateNameError:
            switch error {
            case .noDNSName: return .network("TLS: certificate does not name the host")
            case .noPeerCertificate: return .network("TLS: no peer certificate")
            case .malformedCertificate: return .network("TLS: malformed certificate")
            }
        case is NIOSSLError, is BoringSSLError, is NIOSSLExtraError: return .network("TLS: \(type(of: error))")
        case is ChannelError, is NIOConnectionError, is IOError: return .network("connection failed")
        case is HTTPParserError: return .invalidResponse("malformed HTTP response")
        case is CancellationError: return .cancelled
        default: return .network(String(describing: type(of: error)))
        }
    }
}

/// Per-request state, confined to the request's event loop.
private struct RequestState: Sendable {
    var channel: (any Channel)?
    var aborted: OAuth2Error?
}

/// Completes `ready` once the TLS handshake is done and, for a host name, the verified certificate
/// carries a matching DNS subjectAltName; fails it (and closes) otherwise. The request is written
/// only after `ready` succeeds. Event-loop confined.
private final class TLSReadyGate: ChannelInboundHandler {
    typealias InboundIn = NIOAny
    private let host: String?
    private let ready: EventLoopPromise<Void>

    init(host: String?, ready: EventLoopPromise<Void>) {
        self.host = host
        self.ready = ready
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let tlsEvent = event as? TLSUserEvent, case .handshakeCompleted = tlsEvent {
            do {
                if let host { try CertificateDNSNames.requireMatch(in: context.pipeline.syncOperations, host: host) }
                ready.succeed(())
            } catch {
                ready.fail(error)
                context.fireErrorCaught(error)
                context.close(promise: nil)
                return
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        ready.fail(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        ready.fail(OAuth2Error.network("connection closed during the TLS handshake"))
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        ready.fail(OAuth2Error.network("connection closed during the TLS handshake"))
    }
}

/// Collects one HTTP response, failing (and closing) as soon as the body would pass `limit`, or on a
/// compressed body. Event-loop confined.
private final class CappedResponseCollector: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart

    private let limit: Int
    private let promise: EventLoopPromise<OAuth2HTTPResponse>
    private var status: Int?
    private var body: [UInt8] = []
    private var done = false

    init(limit: Int, promise: EventLoopPromise<OAuth2HTTPResponse>) {
        self.limit = limit
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !done else { return }
        switch Self.unwrapInboundIn(data) {
        case .head(let head):
            guard head.status.code >= 200 else { return }  // 1xx interim responses
            if let length = head.headers.first(name: "Content-Length").flatMap(Int.init), length > limit {
                finish(context, .failure(OAuth2Error.responseTooLarge(limit: limit)))
                return
            }
            // Every Content-Encoding header and list element, not only the first.
            let encodings = head.headers[canonicalForm: "Content-Encoding"].map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            if let encoding = encodings.first(where: { !$0.isEmpty && $0 != "identity" }) {
                finish(context, .failure(OAuth2Error.invalidResponse("compressed response refused (Content-Encoding: \(encoding.prefix(32)))")))
                return
            }
            // Only plain chunked framing: `gzip, chunked` would hand the collector a compressed body.
            let transferCodings = head.headers[canonicalForm: "Transfer-Encoding"].map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            if !transferCodings.isEmpty, transferCodings != ["chunked"] {
                finish(context, .failure(OAuth2Error.invalidResponse("unsupported Transfer-Encoding (\(transferCodings.joined(separator: ", ").prefix(32)))")))
                return
            }
            status = Int(head.status.code)
        case .body(var buffer):
            guard status != nil else { return }
            if body.count + buffer.readableBytes > limit {
                finish(context, .failure(OAuth2Error.responseTooLarge(limit: limit)))
                return
            }
            body.append(contentsOf: buffer.readBytes(length: buffer.readableBytes) ?? [])
        case .end:
            guard let status else { return }
            finish(context, .success(OAuth2HTTPResponse(status: status, body: Data(body))))
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish(context, .failure(OAuth2Error.network("connection closed before the response was complete")))
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        finish(context, .failure(error))
    }

    private func finish(_ context: ChannelHandlerContext, _ result: Result<OAuth2HTTPResponse, any Error>) {
        guard !done else { return }
        done = true
        body = []
        promise.completeWith(result)
        // Stop reading before closing, so nothing more is pulled off the socket while the close
        // (and any TLS shutdown) completes.
        try? context.channel.syncOptions?.setOption(.autoRead, value: false)
        context.close(promise: nil)
    }
}
