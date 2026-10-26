import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import Testing
@testable import PerfectOAuth2
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A transport that trusts the test CA and connects every name to the test server on 127.0.0.1.
func testTransport(_ server: NIOTestServer, timeout: TimeInterval = 10, limit: Int = 1 << 20, trust: String = TestCertificates.caPEM) throws -> NIOTransport {
    var tls = TLSConfiguration.makeClientConfiguration()
    tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(trust.utf8)))
    let port = server.port
    return NIOTransport(timeout: timeout, maximumResponseBytes: limit, tlsConfiguration: tls,
                        addressOverride: { _, _ in try? SocketAddress(ipAddress: "127.0.0.1", port: port) })
}

func openFileDescriptors() -> Int {
    #if os(Linux)
    return (try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fd").count) ?? -1
    #else
    return (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1
    #endif
}

private func get(_ transport: NIOTransport, _ url: String) async throws -> OAuth2HTTPResponse {
    try await transport.send(OAuth2HTTPRequest(method: .get, url: URL(string: url)!))
}

private func json(_ body: String, status: Int = 200, headers: [String: String] = [:]) -> NIOTestServer.Behavior {
    .respond(status: status, headers: headers.merging(["Content-Type": "application/json"]) { a, _ in a }, body: Data(body.utf8))
}

/// Waits (up to 5 s) for the server to see every connection closed.
private func settle(_ server: NIOTestServer) async {
    for _ in 0..<100 where server.openConnections > 0 { try? await Task.sleep(nanoseconds: 50_000_000) }
}

@Suite("NIOTransport", .serialized)
struct NIOTransportTests {
    @Test func postOverTLSWithSNIAndHostHeader() async throws {
        let server = try NIOTestServer { _ in json(#"{"access_token":"AT"}"#) }
        defer { server.stop() }
        let oauth = OAuth2(
            configuration: OAuth2ClientConfiguration(clientID: "id", clientSecret: "secret-value-123", redirectURL: URL(string: "https://app.test/cb")!,
                                                     usePKCE: false, http: OAuth2HTTPOptions(transport: try testTransport(server))),
            authorizationURL: URL(string: "https://auth.test/a")!, tokenURL: URL(string: "\(server.baseURL)/oauth/token?x=1")!
        )
        let token = try await oauth.refresh(refreshToken: "refresh-value")
        #expect(token.accessToken == "AT")
        let request = try #require(server.requests.first)
        #expect(request.head.hasPrefix("POST /oauth/token?x=1 HTTP/1.1"))
        let head = request.head.lowercased()
        #expect(head.contains("host: auth.test:\(server.port)"))
        #expect(head.contains("accept-encoding: identity"))
        #expect(head.contains("content-type: application/x-www-form-urlencoded"))
        #expect(head.contains("connection: close"))
        #expect(formFields(request.body)["refresh_token"] == "refresh-value")
        await settle(server)
        #expect(server.openConnections == 0)
    }

    @Test func plainHTTPOnlyToLoopback() async throws {
        let server = try NIOTestServer(certificate: nil) { _ in json("{}") }
        defer { server.stop() }
        let transport = NIOTransport(timeout: 5)
        #expect(try await get(transport, "http://127.0.0.1:\(server.port)/x").status == 200)
        await #expect(throws: OAuth2Error.insecureURL("request URL must use https")) {
            try await get(transport, "http://auth.test:\(server.port)/x")
        }
    }

    @Test(arguments: [301, 302, 303, 307, 308])
    func redirectsAreReturnedNotFollowed(code: Int) async throws {
        let target = try NIOTestServer { _ in json(#"{"access_token":"stolen"}"#) }
        defer { target.stop() }
        let server = try NIOTestServer { _ in .respond(status: code, headers: ["Location": "\(target.baseURL)/steal"], body: Data()) }
        defer { server.stop() }
        let response = try await get(try testTransport(server), "\(server.baseURL)/token")
        #expect(response.status == code)
        #expect(target.requests.isEmpty)
    }

    @Test func endlessBodiesStopAtTheCap() async throws {
        for behavior in [NIOTestServer.Behavior.endless, .endlessChunked] {
            let server = try NIOTestServer { _ in behavior }
            defer { server.stop() }
            let start = Date()
            await #expect(throws: OAuth2Error.responseTooLarge(limit: 64 * 1024)) {
                try await get(try testTransport(server, limit: 64 * 1024), "\(server.baseURL)/t")
            }
            #expect(Date().timeIntervalSince(start) < 2)
            await settle(server)
            #expect(server.openConnections == 0)
            // The connection was closed at the cap: the server stops being able to write.
            let sent = server.totalBytesSent
            try await Task.sleep(nanoseconds: 300_000_000)
            #expect(server.totalBytesSent - sent < 1 << 20)
        }
    }

    @Test func hugeContentLengthIsRefusedUpFront() async throws {
        let server = try NIOTestServer { _ in .rawHead("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n") }
        defer { server.stop() }
        await #expect(throws: OAuth2Error.responseTooLarge(limit: 1 << 20)) {
            try await get(try testTransport(server), "\(server.baseURL)/t")
        }
    }

    @Test func compressedBodiesAreRefused() async throws {
        for encoding in ["gzip", "br", "deflate", " GZIP "] {
            let server = try NIOTestServer { _ in .respond(status: 200, headers: ["Content-Encoding": encoding], body: Data(repeating: 0x1f, count: 64)) }
            defer { server.stop() }
            let error = await #expect(throws: OAuth2Error.self) { try await get(try testTransport(server), "\(server.baseURL)/t") }
            guard case .invalidResponse(let why)? = error else { Issue.record("\(String(describing: error))"); continue }
            #expect(why.hasPrefix("compressed response refused"))
        }
    }

    @Test func slowLorisAndSilentServersHitTheDeadline() async throws {
        for behavior in [NIOTestServer.Behavior.drip(declared: 1000, interval: 0.2), .silent] {
            let server = try NIOTestServer { _ in behavior }
            defer { server.stop() }
            let start = Date()
            await #expect(throws: OAuth2Error.timedOut) { try await get(try testTransport(server, timeout: 1.5), "\(server.baseURL)/t") }
            let elapsed = Date().timeIntervalSince(start)
            #expect(elapsed >= 1.4 && elapsed < 4)
            await settle(server)
            #expect(server.openConnections == 0)
        }
    }

    @Test func deadlineDuringTheHandshakeSendsNothing() async throws {
        // A plain TCP server that never speaks TLS: the handshake stalls until the deadline.
        let server = try NIOTestServer(certificate: nil) { _ in .silent }
        defer { server.stop() }
        await #expect(throws: OAuth2Error.timedOut) { try await get(try testTransport(server, timeout: 1), "\(server.baseURL)/t") }
        #expect(server.requests.isEmpty)
    }

    @Test func cancellationEndsTheRequest() async throws {
        let server = try NIOTestServer { _ in .silent }
        defer { server.stop() }
        let transport = try testTransport(server, timeout: 30)
        let task = Task { try await get(transport, "\(server.baseURL)/t") }
        try await Task.sleep(nanoseconds: 300_000_000)
        let start = Date()
        task.cancel()
        let result = await task.result
        #expect(Date().timeIntervalSince(start) < 2)
        guard case .failure(OAuth2Error.network("cancelled")) = result else { Issue.record("\(result)"); return }
    }

    @Test func connectionRefused() async throws {
        let server = try NIOTestServer { _ in .silent }
        let port = server.port
        server.stop()
        let transport = NIOTransport(timeout: 5, addressOverride: { _, _ in try? SocketAddress(ipAddress: "127.0.0.1", port: port) })
        await #expect(throws: OAuth2Error.network("connection failed")) { try await get(transport, "https://auth.test:\(port)/t") }
    }
}

@Suite("NIOTransport certificates", .serialized)
struct NIOTransportCertificateTests {
    /// Every refusal happens before the request is written: the server never sees it.
    private func expectRefused(_ certificate: NIOTestServer.Certificate, host: String = "auth.test", trust: String = TestCertificates.caPEM, message: String) async throws {
        let server = try NIOTestServer(certificate: certificate) { _ in json(#"{"access_token":"AT"}"#) }
        defer { server.stop() }
        let error = await #expect(throws: OAuth2Error.self) {
            try await get(try testTransport(server, trust: trust), "https://\(host):\(server.port)/token")
        }
        guard case .network(let why)? = error else { Issue.record("\(String(describing: error))"); return }
        #expect(why.hasPrefix(message), "\(why)")
        #expect(server.requests.isEmpty)
        await settle(server)
        #expect(server.openConnections == 0)
    }

    @Test func ipOnlyCertificateIsRefusedForAName() async throws {
        // NIOSSL alone accepts an IP SAN equal to the dialed address (127.0.0.1); the DNS-SAN check doesn't.
        try await expectRefused(.ipOnly, message: "TLS")
    }

    @Test func wrongNameIsRefused() async throws {
        try await expectRefused(.wrongName, message: "TLS")
    }

    @Test func untrustedCAIsRefused() async throws {
        try await expectRefused(.untrusted, message: "TLS")
    }

    @Test func wildcardCoversExactlyOneLabel() async throws {
        let server = try NIOTestServer(certificate: .wildcard) { _ in json("{}") }
        defer { server.stop() }
        #expect(try await get(try testTransport(server), "https://login.wild.test:\(server.port)/t").status == 200)
        try await expectRefused(.wildcard, host: "a.b.wild.test", message: "TLS")
        try await expectRefused(.wildcard, host: "wild.test", message: "TLS")
    }

    @Test func ipLiteralUsesNIOSSLsIPCheck() async throws {
        let server = try NIOTestServer(certificate: .ipOnly) { _ in json("{}") }
        defer { server.stop() }
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(TestCertificates.caPEM.utf8)))
        let transport = NIOTransport(timeout: 5, tlsConfiguration: tls)
        #expect(try await get(transport, "https://127.0.0.1:\(server.port)/t").status == 200)
    }

    @Test func certificateNameParsing() throws {
        func der(_ pem: String) throws -> [UInt8] { try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8))[0].toDERBytes() }
        #expect(try CertificateDNSNames.dnsNames(fromDER: der(TestCertificates.namedCertificatePEM)) == ["auth.test"])
        #expect(try CertificateDNSNames.dnsNames(fromDER: der(TestCertificates.ipOnlyCertificatePEM)) == [])
        #expect(try CertificateDNSNames.dnsNames(fromDER: der(TestCertificates.wildcardCertificatePEM)) == ["*.wild.test"])
        #expect(throws: CertificateNameError.self) { try CertificateDNSNames.dnsNames(fromDER: [0x30, 0x03, 0x02, 0x01]) }
        for (pattern, host, ok) in [("auth.test", "AUTH.test", true), ("auth.test", "auth.test.", true), ("*.wild.test", "a.wild.test", true),
                                    ("*.wild.test", "wild.test", false), ("*.wild.test", "a.b.wild.test", false), ("*.", "a", false),
                                    ("a*.wild.test", "ab.wild.test", false)] {
            #expect(CertificateDNSNames.matches(pattern: pattern, host: host) == ok, "\(pattern) \(host)")
        }
    }
}

@Suite("NIOTransport resource use", .serialized)
struct NIOTransportResourceTests {
    /// Back-to-back capped calls against an endless body: each returns at the cap, connections are
    /// closed, and descriptors don't accumulate. With MEASURE_CALLS set, prints the numbers.
    @Test func cappedCallsDoNotLeak() async throws {
        let calls = Int(ProcessInfo.processInfo.environment["MEASURE_CALLS"] ?? "") ?? 20
        let server = try NIOTestServer { _ in .endless }
        defer { server.stop() }
        let transport = try testTransport(server, timeout: 5, limit: 16 * 1024)
        _ = try? await get(transport, "\(server.baseURL)/warm")
        await settle(server)
        let fdBefore = openFileDescriptors()
        let start = Date()
        var slowest = 0.0
        for _ in 0..<calls {
            let callStart = Date()
            await #expect(throws: OAuth2Error.responseTooLarge(limit: 16 * 1024)) { try await get(transport, "\(server.baseURL)/t") }
            slowest = max(slowest, Date().timeIntervalSince(callStart))
        }
        let elapsed = Date().timeIntervalSince(start)
        let sentAtReturn = server.totalBytesSent
        await settle(server)
        try await Task.sleep(nanoseconds: 1_000_000_000)
        let fdAfter = openFileDescriptors()
        if ProcessInfo.processInfo.environment["MEASURE_CALLS"] != nil {
            var usage = rusage()
            #if os(Linux)
            getrusage(__rusage_who_t(RUSAGE_SELF.rawValue), &usage)
            let rssMB = Int(usage.ru_maxrss) / 1024
            #else
            getrusage(RUSAGE_SELF, &usage)
            let rssMB = Int(usage.ru_maxrss) / (1024 * 1024)
            #endif
            print(String(format: "MEASURE %d capped calls: %.2fs total, slowest %.3fs, server sent %d MB (+%d MB after), fd %d -> %d, open server connections %d, max RSS %d MB",
                         calls, elapsed, slowest, sentAtReturn >> 20, (server.totalBytesSent - sentAtReturn) >> 20, fdBefore, fdAfter, server.openConnections, rssMB))
        }
        #expect(server.openConnections == 0)
        #expect(fdAfter <= fdBefore + 2)
        #expect(slowest < 2)
    }

    @Test func failingCallsDoNotLeak() async throws {
        let server = try NIOTestServer(certificate: .wrongName) { _ in json("{}") }
        defer { server.stop() }
        let transport = try testTransport(server, timeout: 5)
        _ = try? await get(transport, "\(server.baseURL)/warm")
        let fdBefore = openFileDescriptors()
        for _ in 0..<50 { _ = try? await get(transport, "\(server.baseURL)/t") }
        await settle(server)
        #expect(server.openConnections == 0)
        #expect(server.requests.isEmpty)
        #expect(openFileDescriptors() <= fdBefore + 2)
    }
}
