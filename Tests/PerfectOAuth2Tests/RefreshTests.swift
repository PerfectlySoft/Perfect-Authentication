import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import PerfectOAuth2

/// Intercepts requests to hosts registered with `StubTokenEndpoint.serve(...)` and lets every other
/// request through, so tests using distinct hosts can run in parallel.
final class StubTokenEndpoint: URLProtocol, @unchecked Sendable {
    struct Captured: Sendable {
        let method: String?
        let contentType: String?
        let body: String
    }

    private struct Route {
        let status: Int
        let response: Data
        var captured: [Captured] = []
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var routes: [String: Route] = [:]
    private static let registered: Void = { URLProtocol.registerClass(StubTokenEndpoint.self) }()

    /// Registers a canned response for `https://<host>/token` and returns its URL.
    static func serve(host: String, status: Int = 200, json: String) -> String {
        _ = registered
        lock.withLock { routes[host] = Route(status: status, response: Data(json.utf8)) }
        return "https://\(host)/token"
    }

    static func requests(host: String) -> [Captured] {
        lock.withLock { routes[host]?.captured ?? [] }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        guard let host = request.url?.host else { return false }
        return lock.withLock { routes[host] != nil }
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let host = request.url?.host ?? ""
        let captured = Captured(
            method: request.httpMethod,
            contentType: request.value(forHTTPHeaderField: "Content-Type"),
            body: String(decoding: Self.bodyData(of: request), as: UTF8.self)
        )
        let route: Route? = Self.lock.withLock {
            Self.routes[host]?.captured.append(captured)
            return Self.routes[host]
        }
        guard let route, let url = request.url,
              let response = HTTPURLResponse(url: url, statusCode: route.status, httpVersion: "HTTP/1.1",
                                             headerFields: ["Content-Type": "application/json"])
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: route.response)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    /// URLSession moves `httpBody` into `httpBodyStream` before handing the request to a protocol.
    private static func bodyData(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return data
    }
}

/// Decodes an `application/x-www-form-urlencoded` body into a dictionary (`+` means space).
private func formFields(_ body: String) -> [String: String] {
    var fields: [String: String] = [:]
    for pair in body.split(separator: "&") {
        let parts = pair.replacingOccurrences(of: "+", with: " ")
            .split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let key = String(parts[0]).removingPercentEncoding,
              let value = String(parts[1]).removingPercentEncoding else { continue }
        fields[key] = value
    }
    return fields
}

private func client(tokenURL: String) -> OAuth2 {
    OAuth2(
        clientID: "client id",
        clientSecret: "s3cr3t/+=",
        authorizationURL: "https://auth.invalid/authorize",
        tokenURL: tokenURL
    )
}

@Suite("Refresh token grant")
struct RefreshTests {

    @Test func sendsRefreshGrantAndParsesRotatedToken() async throws {
        let host = "refresh-rotated.test.invalid"
        let url = StubTokenEndpoint.serve(host: host, json: """
            {"access_token":"new-access","token_type":"Bearer","expires_in":3600,
             "refresh_token":"rotated-refresh","scope":"openid email"}
            """)

        let token = try await client(tokenURL: url)
            .refresh(refreshToken: "old/refresh+token", scopes: ["openid", "email"])

        #expect(token.accessToken == "new-access")
        #expect(token.refreshToken == "rotated-refresh")
        #expect(token.tokenType == "Bearer")
        #expect(token.scope == ["openid", "email"])
        #expect(token.expiration != nil)

        let requests = StubTokenEndpoint.requests(host: host)
        try #require(requests.count == 1)
        #expect(requests[0].method == "POST")
        #expect(requests[0].contentType == "application/x-www-form-urlencoded")
        #expect(formFields(requests[0].body) == [
            "grant_type": "refresh_token",
            "refresh_token": "old/refresh+token",
            "client_id": "client id",
            "client_secret": "s3cr3t/+=",
            "scope": "openid email",
        ])
    }

    @Test func keepsOriginalRefreshTokenWhenResponseOmitsIt() async throws {
        let host = "refresh-kept.test.invalid"
        let url = StubTokenEndpoint.serve(host: host, json: """
            {"access_token":"new-access","token_type":"Bearer","expires_in":3599}
            """)

        let token = try await client(tokenURL: url).refresh(refreshToken: "long-lived")

        #expect(token.accessToken == "new-access")
        #expect(token.refreshToken == "long-lived")
        let fields = formFields(try #require(StubTokenEndpoint.requests(host: host).first).body)
        #expect(fields["scope"] == nil)
        #expect(fields["client_secret"] == "s3cr3t/+=")
    }

    @Test func omitsClientSecretForPublicClients() async throws {
        let host = "refresh-public.test.invalid"
        let url = StubTokenEndpoint.serve(host: host, json: #"{"access_token":"a"}"#)

        _ = try await client(tokenURL: url).refresh(refreshToken: "r", includeClientSecret: false)

        let fields = formFields(try #require(StubTokenEndpoint.requests(host: host).first).body)
        #expect(fields["client_secret"] == nil)
        #expect(fields["client_id"] == "client id")
    }

    @Test func throwsOAuth2ErrorForRejectedGrant() async throws {
        let url = StubTokenEndpoint.serve(host: "refresh-rejected.test.invalid", status: 400, json: """
            {"error":"invalid_grant","error_description":"Token has been expired or revoked."}
            """)

        let error = await #expect(throws: OAuth2Error.self) {
            try await client(tokenURL: url).refresh(refreshToken: "revoked")
        }
        #expect(error?.code == .invalidGrant)
        #expect(error?.description == "Token has been expired or revoked.")
    }

    @Test func throwsInvalidAPIResponseForUnexpectedBody() async throws {
        let url = StubTokenEndpoint.serve(host: "refresh-garbage.test.invalid", status: 502, json: "<html>Bad Gateway</html>")

        await #expect(throws: InvalidAPIResponse.self) {
            try await client(tokenURL: url).refresh(refreshToken: "r")
        }
    }
}
