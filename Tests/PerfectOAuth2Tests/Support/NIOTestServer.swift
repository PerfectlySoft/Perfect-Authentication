import Foundation
import NIOCore
import NIOPosix
import NIOSSL

/// A local HTTP/1.1 server on SwiftNIO, with TLS from the test CA, for exercising `NIOTransport`.
/// Same behaviours as `LocalHTTPServer`, plus an endless chunked stream.
final class NIOTestServer: @unchecked Sendable {
    enum Behavior: Sendable {
        case respond(status: Int, headers: [String: String], body: Data)
        /// Headers without a length, then spaces until the client goes away.
        case endless
        /// `Transfer-Encoding: chunked`, then 64 KiB chunks until the client goes away.
        case endlessChunked
        /// `Content-Length: declared`, then one byte every `interval` seconds.
        case drip(declared: Int, interval: TimeInterval)
        /// Writes `head` verbatim (e.g. a huge Content-Length), then nothing.
        case rawHead(String)
        /// Accepts and never answers.
        case silent
    }

    struct Received: Sendable {
        let head: String
        let body: Data
    }

    enum Certificate: Sendable { case named, ipOnly, wrongName, wildcard, untrusted }

    private let channel: any Channel
    private let stats: Stats

    var port: Int { channel.localAddress?.port ?? 0 }
    var baseURL: String { "https://auth.test:\(port)" }
    var requests: [Received] { stats.lock.withLock { stats.received } }
    var totalBytesSent: Int { stats.lock.withLock { stats.bytesSent } }
    var connectionCount: Int { stats.lock.withLock { stats.connections } }
    var openConnections: Int { stats.lock.withLock { stats.open } }

    /// - Parameter certificate: nil for plain HTTP.
    init(certificate: Certificate? = .named, _ behavior: @escaping @Sendable (Received) -> Behavior) throws {
        let context: NIOSSLContext? = try certificate.map { certificate in
            let (cert, key) = Self.pem(for: certificate)
            var configuration = TLSConfiguration.makeServerConfiguration(
                certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(cert.utf8)).map { .certificate($0) },
                privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(key.utf8), format: .pem))
            )
            configuration.minimumTLSVersion = .tlsv12
            return try NIOSSLContext(configuration: configuration)
        }
        let stats = Stats()
        channel = try ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { child in
                child.eventLoop.makeCompletedFuture {
                    if let context {
                        try child.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                    }
                    try child.pipeline.syncOperations.addHandler(RequestHandler(behavior: behavior, stats: stats))
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
        self.stats = stats
    }

    func stop() {
        try? channel.close().wait()
    }

    static func pem(for certificate: Certificate) -> (String, String) {
        switch certificate {
        case .named: (TestCertificates.namedCertificatePEM, TestCertificates.namedKeyPEM)
        case .ipOnly: (TestCertificates.ipOnlyCertificatePEM, TestCertificates.ipOnlyKeyPEM)
        case .wrongName: (TestCertificates.wrongNameCertificatePEM, TestCertificates.wrongNameKeyPEM)
        case .wildcard: (TestCertificates.wildcardCertificatePEM, TestCertificates.wildcardKeyPEM)
        case .untrusted: (TestCertificates.untrustedCertificatePEM, TestCertificates.untrustedKeyPEM)
        }
    }

    final class Stats: @unchecked Sendable {
        let lock = NSLock()
        var received: [Received] = []
        var bytesSent = 0
        var connections = 0
        var open = 0
    }
}

/// Reads one request, then answers per the behaviour. Event-loop confined.
private final class RequestHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let behavior: @Sendable (NIOTestServer.Received) -> NIOTestServer.Behavior
    private let stats: NIOTestServer.Stats
    private var buffer = ByteBuffer()
    private var answered = false
    private var active = true

    init(behavior: @escaping @Sendable (NIOTestServer.Received) -> NIOTestServer.Behavior, stats: NIOTestServer.Stats) {
        self.behavior = behavior
        self.stats = stats
    }

    func channelActive(context: ChannelHandlerContext) {
        stats.lock.withLock {
            stats.connections += 1
            stats.open += 1
        }
        context.fireChannelActive()
    }

    func channelInactive(context: ChannelHandlerContext) {
        active = false
        stats.lock.withLock { stats.open -= 1 }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)
        guard !answered else { return }
        let bytes = Array(buffer.readableBytesView)
        guard let split = Self.find(Array("\r\n\r\n".utf8), in: bytes) else { return }
        let head = String(decoding: bytes[..<split], as: UTF8.self)
        let length = head.split(separator: "\r\n")
            .first { $0.lowercased().hasPrefix("content-length:") }
            .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
        let bodyStart = split + 4
        guard bytes.count - bodyStart >= length else { return }
        answered = true
        let request = NIOTestServer.Received(head: head, body: Data(bytes[bodyStart..<(bodyStart + length)]))
        stats.lock.withLock { stats.received.append(request) }
        respond(context, behavior(request))
    }

    private func respond(_ context: ChannelHandlerContext, _ behavior: NIOTestServer.Behavior) {
        switch behavior {
        case .respond(let status, let headers, let body):
            var head = "HTTP/1.1 \(status) Status\r\nContent-Length: \(body.count)\r\nConnection: close\r\n"
            for (name, value) in headers { head += "\(name): \(value)\r\n" }
            send(context, Array((head + "\r\n").utf8) + Array(body), then: { context.close(promise: nil) })
        case .endless:
            send(context, Array("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".utf8)) {
                self.pump(context, Array(repeating: UInt8(ascii: " "), count: 64 * 1024))
            }
        case .endlessChunked:
            let chunk = Array("10000\r\n".utf8) + Array(repeating: UInt8(ascii: " "), count: 0x10000) + Array("\r\n".utf8)
            send(context, Array("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".utf8)) {
                self.pump(context, chunk)
            }
        case .drip(let declared, let interval):
            send(context, Array("HTTP/1.1 200 OK\r\nContent-Length: \(declared)\r\nConnection: close\r\n\r\n".utf8)) {
                self.drip(context, remaining: declared, interval: interval)
            }
        case .rawHead(let head):
            send(context, Array(head.utf8))
        case .silent:
            break
        }
    }

    private func send(_ context: ChannelHandlerContext, _ bytes: [UInt8], then next: @escaping () -> Void = {}) {
        guard active else { return }
        let count = bytes.count
        let stats = self.stats
        context.writeAndFlush(Self.wrapOutboundOut(ByteBuffer(bytes: bytes))).assumeIsolated().whenComplete { result in
            if case .success = result {
                stats.lock.withLock { stats.bytesSent += count }
                // Hop through the loop: a write that completes synchronously would otherwise recurse
                // (an endless pump overflowed the stack).
                context.eventLoop.assumeIsolated().execute { next() }
            }
        }
    }

    private func pump(_ context: ChannelHandlerContext, _ chunk: [UInt8]) {
        send(context, chunk) { self.pump(context, chunk) }
    }

    private func drip(_ context: ChannelHandlerContext, remaining: Int, interval: TimeInterval) {
        guard remaining > 0, active else { return }
        context.eventLoop.assumeIsolated().scheduleTask(in: .milliseconds(Int64(interval * 1000))) {
            self.send(context, [UInt8(ascii: " ")]) { self.drip(context, remaining: remaining - 1, interval: interval) }
        }
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        for index in 0...(haystack.count - needle.count) where Array(haystack[index..<(index + needle.count)]) == needle {
            return index
        }
        return nil
    }
}
