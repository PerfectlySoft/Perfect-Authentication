import Foundation
import Testing
@testable import PerfectOAuth2

private let tokenURL = "https://auth.test/token"

private func generic(_ transport: StubTransport, pkce: Bool? = nil, redirect: String = "https://app.test/auth/callback", secret: String? = "s3cr3t/+=&") -> OAuth2 {
    OAuth2(
        configuration: testConfiguration(transport: transport, redirect: redirect, usePKCE: pkce, secret: secret),
        authorizationURL: URL(string: "https://auth.test/authorize?tenant=a%20b")!,
        tokenURL: URL(string: tokenURL)!,
        defaultScopes: ["openid", "profile"]
    )
}

@Suite("OAuth2 flow")
struct FlowTests {
    @Test func loginLinkHasEncodedParametersStateAndPKCE() throws {
        let client = generic(StubTransport())
        let request = try client.authorizationRequest(state: validState)
        let query = try #require(queryParameters(request.url))
        #expect(request.url.absoluteString.hasPrefix("https://auth.test/authorize?tenant=a%20b&response_type=code&"))
        #expect(query["tenant"] == "a b")
        #expect(query["response_type"] == "code")
        #expect(query["client_id"] == "client id&x")
        #expect(query["redirect_uri"] == "https://app.test/auth/callback")
        #expect(query["state"] == validState)
        #expect(query["scope"] == "openid profile")
        #expect(query["code_challenge_method"] == "S256")
        let verifier = try #require(request.pending.codeVerifier)
        #expect(query["code_challenge"] == PKCE.challenge(for: verifier))
        #expect(request.pending.state == validState)
        #expect(request.pending.redirectURL.absoluteString == "https://app.test/auth/callback")
        // `&`, `+` and spaces never appear raw in values.
        #expect(request.url.absoluteString.contains("client_id=client%20id%26x"))
    }

    @Test func generatesStateWhenNoneGiven() throws {
        let request = try generic(StubTransport()).authorizationRequest()
        #expect(request.pending.state.count == 43)
        #expect(queryParameters(request.url)?["state"] == request.pending.state)
    }

    @Test func redirectURLWithQueryIsOneEncodedValue() throws {
        let client = generic(StubTransport(), redirect: "https://app.test/cb?tenant=a&b=c+d")
        let request = try client.authorizationRequest(state: validState)
        let query = try #require(queryParameters(request.url))
        #expect(query["redirect_uri"] == "https://app.test/cb?tenant=a&b=c+d")
        #expect(query["b"] == nil)
    }

    @Test func pkceCanBeDisabled() throws {
        let request = try generic(StubTransport(), pkce: false).authorizationRequest(state: validState)
        let query = try #require(queryParameters(request.url))
        #expect(query["code_challenge"] == nil)
        #expect(query["code_challenge_method"] == nil)
        #expect(request.pending.codeVerifier == nil)
    }

    @Test func rejectsBadInputs() {
        let client = generic(StubTransport())
        #expect(throws: OAuth2Error.self) { try client.authorizationRequest(state: "short") }
        #expect(throws: OAuth2Error.self) { try client.authorizationRequest(state: "") }
        #expect(throws: OAuth2Error.self) {
            try client.authorizationRequest(additionalParameters: [URLQueryItem(name: "redirect_uri", value: "https://evil.test")])
        }
        #expect(throws: OAuth2Error.self) {
            try client.authorizationRequest(additionalParameters: [URLQueryItem(name: "state", value: validState)])
        }
        for redirect in ["http://app.test/cb", "https://app.test/cb#frag", "javascript:alert(1)", "ftp://app.test/"] {
            #expect(throws: OAuth2Error.self) {
                try generic(StubTransport(), redirect: redirect).authorizationRequest()
            }
        }
        #expect(throws: Never.self) {
            try generic(StubTransport(), redirect: "http://localhost:8080/cb").authorizationRequest()
        }
    }

    @Test func exchangeSendsCodeVerifierAndRedirect() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT","token_type":"bearer","expires_in":"60","refresh_token":"RT"}"#)
        let client = generic(transport)
        let request = try client.authorizationRequest(state: validState)
        let token = try await client.exchange(callback: AuthorizationCallback(code: "c/o+d=e", state: validState), pending: request.pending)
        #expect(token.accessToken == "AT")
        #expect(token.refreshToken == "RT")
        #expect(token.expiresIn == 60)

        let sent = try #require(transport.requests.first)
        #expect(sent.method == .post)
        #expect(sent.headers["Content-Type"] == "application/x-www-form-urlencoded")
        #expect(sent.headers["Accept"] == "application/json")
        #expect(formFields(sent.body) == [
            "grant_type": "authorization_code",
            "code": "c/o+d=e",
            "redirect_uri": "https://app.test/auth/callback",
            "client_id": "client id&x",
            "client_secret": "s3cr3t/+=&",
            "code_verifier": request.pending.codeVerifier!,
        ])
    }

    @Test func publicClientOmitsSecret() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let client = generic(transport, secret: nil)
        let request = try client.authorizationRequest(state: validState)
        _ = try await client.exchange(callback: AuthorizationCallback(code: "c", state: validState), pending: request.pending)
        #expect(formFields(transport.requests.first?.body)["client_secret"] == nil)
    }

    @Test func stateIsCheckedBeforeAnyRequest() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let client = generic(transport)
        let request = try client.authorizationRequest(state: validState)
        for state in [nil, "", "wrong", validState + "x"] as [String?] {
            await #expect(throws: OAuth2Error.stateMismatch) {
                try await client.exchange(callback: AuthorizationCallback(code: "c", state: state), pending: request.pending)
            }
        }
        let emptyPending = PendingAuthorization(state: "", codeVerifier: request.pending.codeVerifier, redirectURL: request.pending.redirectURL, tokenURL: client.tokenURL, clientID: client.clientID)
        await #expect(throws: OAuth2Error.self) {
            try await client.exchange(callback: AuthorizationCallback(code: "c", state: ""), pending: emptyPending)
        }
        #expect(transport.requests.isEmpty)
    }

    @Test func providerErrorOnCallbackAndMissingCode() async throws {
        let client = generic(StubTransport())
        let request = try client.authorizationRequest(state: validState)
        let denied = AuthorizationCallback(url: URL(string: "https://app.test/auth/callback?error=access_denied&state=\(validState)")!)
        await #expect(throws: OAuth2Error.authorizationDenied(OAuth2ErrorResponse(code: "access_denied"))) {
            try await client.exchange(callback: denied, pending: request.pending)
        }
        await #expect(throws: OAuth2Error.missingAuthorizationCode) {
            try await client.exchange(callback: AuthorizationCallback(code: "", state: validState), pending: request.pending)
        }
        let noVerifier = PendingAuthorization(state: validState, codeVerifier: nil, redirectURL: request.pending.redirectURL, tokenURL: client.tokenURL, clientID: client.clientID)
        await #expect(throws: OAuth2Error.self) {
            try await client.exchange(callback: AuthorizationCallback(code: "c", state: validState), pending: noVerifier)
        }
    }

    @Test func pendingAuthorizationRoundTripsThroughJSON() throws {
        let request = try generic(StubTransport()).authorizationRequest()
        let data = try JSONEncoder().encode(request.pending)
        #expect(try JSONDecoder().decode(PendingAuthorization.self, from: data) == request.pending)
    }
}

@Suite("Error mapping")
struct ErrorMappingTests {
    private func exchange(status: Int, body: String) async throws -> OAuth2Token {
        let transport = StubTransport().on(tokenURL, status: status, body)
        let client = generic(transport, pkce: false)
        let pending = PendingAuthorization(state: validState, codeVerifier: nil, redirectURL: URL(string: "https://app.test/auth/callback")!, tokenURL: client.tokenURL, clientID: client.clientID)
        return try await client.exchange(callback: AuthorizationCallback(code: "the-code-123", state: validState), pending: pending)
    }

    @Test func rfc6749ErrorWithAnyStatus() async {
        for status in [200, 400, 401] {
            let error = await #expect(throws: OAuth2Error.self) {
                try await exchange(status: status, body: #"{"error":"invalid_grant","error_description":"Bad code","error_uri":"https://x.test"}"#)
            }
            guard case .providerError(let response)? = error else { Issue.record("\(String(describing: error))"); continue }
            #expect(response.standardCode == .invalidGrant)
            #expect(response.errorDescription == "Bad code")
            #expect(response.errorURI == "https://x.test")
        }
    }

    @Test func nonStandardCodesAreKept() async {
        // GitHub: HTTP 200 with an error field. 1.x turned unknown codes into InvalidAPIResponse.
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "bad_verification_code", errorDescription: "The code passed is incorrect or expired."))) {
            try await exchange(status: 200, body: #"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}"#)
        }
        // Slack
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "invalid_code"))) {
            try await exchange(status: 200, body: #"{"ok":false,"error":"invalid_code"}"#)
        }
        // Facebook Graph
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "OAuthException", errorDescription: "Invalid verification code format."))) {
            try await exchange(status: 400, body: #"{"error":{"message":"Invalid verification code format.","type":"OAuthException","code":100}}"#)
        }
    }

    @Test func statusAndShapeErrors() async {
        // 1.x accepted this: a 500 with an access_token was a successful exchange.
        await #expect(throws: OAuth2Error.httpStatus(500)) {
            try await exchange(status: 500, body: #"{"access_token":"AT"}"#)
        }
        await #expect(throws: OAuth2Error.httpStatus(502)) { try await exchange(status: 502, body: "<html>Bad Gateway</html>") }
        await #expect(throws: OAuth2Error.httpStatus(302)) { try await exchange(status: 302, body: "") }
        await #expect(throws: OAuth2Error.invalidResponse("response is not JSON")) { try await exchange(status: 200, body: "access_token=AT") }
        await #expect(throws: OAuth2Error.invalidResponse("response is not a JSON object")) { try await exchange(status: 200, body: "[1]") }
        await #expect(throws: OAuth2Error.invalidResponse("token response has no access_token")) { try await exchange(status: 200, body: "{}") }
    }

    @Test func providerTextIsSanitisedAndSecretsRedacted() async {
        let error = await #expect(throws: OAuth2Error.self) {
            try await exchange(status: 400, body: #"{"error":"invalid_client\r\nX: y","error_description":"bad secret s3cr3t/+=& for code the-code-123\u0007 \#(String(repeating: "x", count: 400))"}"#)
        }
        let text = "\(String(describing: error))"
        #expect(!text.contains("s3cr3t"))
        #expect(!text.contains("the-code-123"))
        #expect(!text.contains("\r") && !text.contains("\n") && !text.contains("\u{7}"))
        #expect(text.contains("<redacted>"))
        guard case .providerError(let response)? = error else { Issue.record("wrong error"); return }
        #expect((response.errorDescription?.count ?? 0) <= 257)
    }

    @Test func oversizedBodyFromCustomTransportIsRejected() async {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"\#(String(repeating: "a", count: 2000))"}"#)
        let configuration = OAuth2ClientConfiguration(
            clientID: "id", clientSecret: "s", redirectURL: URL(string: "https://app.test/cb")!, usePKCE: false,
            http: OAuth2HTTPOptions(maximumResponseBytes: 1000, transport: transport)
        )
        let client = OAuth2(configuration: configuration, authorizationURL: URL(string: "https://a.test/a")!, tokenURL: URL(string: tokenURL)!)
        await #expect(throws: OAuth2Error.responseTooLarge(limit: 1000)) {
            try await client.refresh(refreshToken: "r")
        }
    }

    @Test func insecureEndpointsAreRefused() async {
        let configuration = testConfiguration(transport: StubTransport())
        let client = OAuth2(configuration: configuration, authorizationURL: URL(string: "http://a.test/a")!, tokenURL: URL(string: "http://a.test/t")!)
        #expect(throws: OAuth2Error.insecureURL("authorization URL must use https")) { try client.authorizationRequest() }
        await #expect(throws: OAuth2Error.insecureURL("token URL must use https")) { try await client.refresh(refreshToken: "r") }
        await #expect(throws: OAuth2Error.insecureURL("API URL must use https")) {
            try await client.getJSON(URL(string: "http://api.test/me")!, accessToken: "AT")
        }
    }
}

@Suite("Refresh grant")
struct RefreshTests {
    @Test func sendsRefreshGrantAndParsesRotatedToken() async throws {
        let transport = StubTransport().on(tokenURL, """
            {"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated","scope":"openid email"}
            """)
        let token = try await generic(transport).refresh(refreshToken: "old/refresh+token", scopes: ["openid", "email"])
        #expect(token.accessToken == "new-access")
        #expect(token.refreshToken == "rotated")
        #expect(token.scope == ["openid", "email"])
        let sent = try #require(transport.requests.first)
        #expect(sent.method == .post)
        #expect(formFields(sent.body) == [
            "grant_type": "refresh_token",
            "refresh_token": "old/refresh+token",
            "client_id": "client id&x",
            "client_secret": "s3cr3t/+=&",
            "scope": "openid email",
        ])
    }

    @Test func keepsOriginalRefreshTokenWhenNotRotated() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"new","expires_in":3599}"#)
        let token = try await generic(transport).refresh(refreshToken: "long-lived")
        #expect(token.refreshToken == "long-lived")
        #expect(token.expiresIn == 3599)
        #expect(token.expiration != nil)
        #expect(formFields(transport.requests.first?.body)["scope"] == nil)
    }

    @Test func omitsSecretWhenAsked() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"a"}"#)
        _ = try await generic(transport).refresh(refreshToken: "r", includeClientSecret: false)
        #expect(formFields(transport.requests.first?.body)["client_secret"] == nil)
    }

    @Test func rejectedGrant() async {
        let transport = StubTransport().on(tokenURL, status: 400, #"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#)
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "invalid_grant", errorDescription: "Token has been expired or revoked."))) {
            try await generic(transport).refresh(refreshToken: "revoked")
        }
    }
}

@Suite("Redaction")
struct RedactionTests {
    private func rendered(_ value: Any) -> String {
        var text = "\(value) \(String(reflecting: value))"
        dump(value, to: &text)
        text += Mirror(reflecting: value).children.map { "\($0.label ?? ""): \($0.value)" }.joined()
        return text
    }

    @Test func secretsNeverAppear() throws {
        let configuration = OAuth2ClientConfiguration(clientID: "id", clientSecret: "TOP-SECRET", redirectURL: URL(string: "https://app.test/cb")!)
        let token = OAuth2Token(accessToken: "ACCESS-TOK", refreshToken: "REFRESH-TOK", idToken: "ID-TOK")
        let profile = try OAuthUserProfile(userid: "42", loginType: "x", token: token)
        let pending = PendingAuthorization(state: "STATE-VALUE-0123456789-0123456789", codeVerifier: "VERIFIER-VALUE", redirectURL: URL(string: "https://app.test/cb")!, nonce: "NONCE-VALUE", tokenURL: URL(string: "https://a.test/t")!, clientID: "id")
        let google = Google(configuration: configuration)
        let request = OAuth2HTTPRequest(method: .post, url: URL(string: "https://a.test/t?x=1")!, headers: ["Authorization": "Bearer ACCESS-TOK"], body: Data("client_secret=TOP-SECRET".utf8))
        let all = [configuration, token, profile, pending, google, google.oauth2, request] as [Any]
        let text = all.map(rendered).joined(separator: "\n")
        for secret in ["TOP-SECRET", "ACCESS-TOK", "REFRESH-TOK", "ID-TOK", "VERIFIER-VALUE", "STATE-VALUE"] {
            #expect(!text.contains(secret), "\(secret) leaked")
        }
        #expect(text.contains("<redacted>"))
    }
}
