import Foundation
import Testing
@testable import PerfectOAuth2

/// Both built-in transports, over plain HTTP to a real socket on 127.0.0.1.
enum TransportKind: String, CaseIterable, Sendable, CustomTestStringConvertible {
    case nio, urlSession
    var testDescription: String { rawValue }

    func make(timeout: TimeInterval, limit: Int) -> any OAuth2Transport {
        switch self {
        case .nio: NIOTransport(timeout: timeout, maximumResponseBytes: limit)
        case .urlSession: URLSessionTransport(timeout: timeout, maximumResponseBytes: limit)
        }
    }
}

extension TransportSuites {
    @Suite("Transports over loopback HTTP", .serialized)
    struct TransportTests {
        private func client(_ kind: TransportKind, _ server: LocalHTTPServer, timeout: TimeInterval = 10, limit: Int = 1 << 20) -> OAuth2 {
            OAuth2(
                configuration: OAuth2ClientConfiguration(
                    clientID: "id", clientSecret: "secret-value-123", redirectURL: URL(string: "https://app.test/cb")!,
                    usePKCE: false, http: OAuth2HTTPOptions(timeout: timeout, maximumResponseBytes: limit, transport: kind.make(timeout: timeout, limit: limit))
                ),
                authorizationURL: URL(string: "https://auth.test/a")!,
                tokenURL: URL(string: "\(server.baseURL)/token")!
            )
        }

        private static func json(_ status: Int, _ body: String, headers: [String: String] = [:]) -> LocalHTTPServer.Behavior {
            .respond(status: status, headers: headers.merging(["Content-Type": "application/json"]) { a, _ in a }, body: Data(body.utf8))
        }

        @Test(arguments: TransportKind.allCases) func postsFormAndParsesJSON(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in Self.json(200, #"{"access_token":"AT","expires_in":10}"#) }
            defer { server.stop() }
            let token = try await client(kind, server).refresh(refreshToken: "refresh-value")
            #expect(token.accessToken == "AT")
            let request = try #require(server.requests.first)
            #expect(request.head.hasPrefix("POST /token HTTP/1.1"))
            #expect(request.head.lowercased().contains("content-type: application/x-www-form-urlencoded"))
            #expect(request.head.lowercased().contains("user-agent: perfectoauth2/2.0"))
            #expect(formFields(request.body)["refresh_token"] == "refresh-value")
        }

        @Test(arguments: TransportKind.allCases) func bearerHeaderOnGet(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in Self.json(200, #"{"sub":"1"}"#) }
            defer { server.stop() }
            let json = try await client(kind, server).getJSON(URL(string: "\(server.baseURL)/me")!, accessToken: "AT-123")
            #expect(json["sub"]?.stringValue == "1")
            let head = try #require(server.requests.first?.head)
            #expect(head.hasPrefix("GET /me HTTP/1.1"))
            #expect(head.contains("Authorization: Bearer AT-123") || head.contains("authorization: Bearer AT-123"))
        }

        @Test(arguments: TransportKind.allCases) func statusAndBodyErrors(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { request in
                if request.head.hasPrefix("POST /token?") { return Self.json(400, #"{"error":"invalid_grant"}"#) }
                return Self.json(503, "<html>down</html>")
            }
            defer { server.stop() }
            await #expect(throws: OAuth2Error.httpStatus(503)) { try await client(kind, server).refresh(refreshToken: "r") }
        }

        @Test(arguments: TransportKind.allCases) func redirectsAreNotFollowed(kind: TransportKind) async throws {
            let target = try LocalHTTPServer { _ in Self.json(200, #"{"access_token":"stolen"}"#) }
            defer { target.stop() }
            let server = try LocalHTTPServer { _ in
                .respond(status: 307, headers: ["Location": "\(target.baseURL)/steal"], body: Data())
            }
            defer { server.stop() }
            await #expect(throws: OAuth2Error.httpStatus(307)) { try await client(kind, server).refresh(refreshToken: "r") }
            #expect(target.requests.isEmpty)
        }

        @Test(arguments: TransportKind.allCases) func declaredOversizeIsRefused(kind: TransportKind) async throws {
            let big = String(repeating: " ", count: 5000) + #"{"access_token":"AT"}"#
            let server = try LocalHTTPServer { _ in Self.json(200, big) }
            defer { server.stop() }
            await #expect(throws: OAuth2Error.responseTooLarge(limit: 4096)) {
                try await client(kind, server, limit: 4096).refresh(refreshToken: "r")
            }
        }

        @Test(arguments: TransportKind.allCases) func endlessBodyStopsAtTheLimit(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .endless }
            defer { server.stop() }
            let start = Date()
            await #expect(throws: OAuth2Error.responseTooLarge(limit: 64 * 1024)) {
                try await client(kind, server, timeout: 20, limit: 64 * 1024).refresh(refreshToken: "r")
            }
            // The call returns as soon as the limit is passed, well before the deadline. (On Linux,
            // corelibs Foundation may go on reading and discarding in the background; see the README.)
            #expect(Date().timeIntervalSince(start) < 5)
        }

        @Test(arguments: TransportKind.allCases) func slowDripHitsTheWholeRequestDeadline(kind: TransportKind) async throws {
            // One byte every 0.2 s never trips URLSession's idle timeout; the deadline must.
            let server = try LocalHTTPServer { _ in .drip(declared: 1000, interval: 0.2) }
            defer { server.stop() }
            let start = Date()
            await #expect(throws: OAuth2Error.timedOut) { try await client(kind, server, timeout: 1.5).refresh(refreshToken: "r") }
            let elapsed = Date().timeIntervalSince(start)
            #expect(elapsed >= 1.4 && elapsed < 5)
        }

        @Test(arguments: TransportKind.allCases) func silentServerTimesOut(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .silent }
            defer { server.stop() }
            await #expect(throws: OAuth2Error.timedOut) { try await client(kind, server, timeout: 1).refresh(refreshToken: "r") }
        }

        @Test(arguments: TransportKind.allCases) func connectionRefusedIsANetworkError(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .silent }
            let url = server.baseURL
            server.stop()
            let client = OAuth2(
                configuration: OAuth2ClientConfiguration(clientID: "id", clientSecret: nil, redirectURL: URL(string: "https://app.test/cb")!, http: OAuth2HTTPOptions(timeout: 5, transport: kind.make(timeout: 5, limit: 1 << 20))),
                authorizationURL: URL(string: "https://auth.test/a")!, tokenURL: URL(string: "\(url)/token")!
            )
            let error = await #expect(throws: OAuth2Error.self) { try await client.refresh(refreshToken: "r") }
            if case .network? = error {} else { Issue.record("expected .network, got \(String(describing: error))") }
        }

        @Test(arguments: TransportKind.allCases) func cancellationEndsTheRequest(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .silent }
            defer { server.stop() }
            let oauth = client(kind, server, timeout: 30)
            let task = Task { try await oauth.refresh(refreshToken: "r") }
            try await Task.sleep(nanoseconds: 300_000_000)
            let start = Date()
            task.cancel()
            let result = await task.result
            #expect(Date().timeIntervalSince(start) < 3)
            if case .success = result { Issue.record("cancelled request succeeded") }
        }

        @Test(arguments: TransportKind.allCases) func concurrentRequests(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in Self.json(200, #"{"access_token":"AT"}"#) }
            defer { server.stop() }
            let oauth = client(kind, server)
            try await withThrowingTaskGroup(of: String.self) { group in
                for _ in 0..<20 { group.addTask { try await oauth.refresh(refreshToken: "r").accessToken } }
                for try await token in group { #expect(token == "AT") }
            }
        }
    }
}
