import Foundation
import Testing
@testable import PerfectOAuth2

private let tokenURL = "https://auth.test/token"

private func client(_ transport: StubTransport, pkce: Bool? = nil, secret: String? = "s3cr3t/+=&", maxAge: TimeInterval = 600) -> OAuth2 {
    var configuration = testConfiguration(transport: transport, usePKCE: pkce, secret: secret)
    configuration.pendingAuthorizationMaxAge = maxAge
    return OAuth2(configuration: configuration, authorizationURL: URL(string: "https://auth.test/authorize")!, tokenURL: URL(string: tokenURL)!)
}

private func callback(_ request: AuthorizationRequest, code: String = "CODE") -> AuthorizationCallback {
    AuthorizationCallback(code: code, state: request.pending.state)
}

private func copy(_ p: PendingAuthorization, verifier: String?? = .none, redirect: URL? = nil, tokenURL: URL? = nil, clientID: String? = nil, createdAt: Date? = nil) -> PendingAuthorization {
    PendingAuthorization(
        state: p.state, codeVerifier: verifier ?? p.codeVerifier, redirectURL: redirect ?? p.redirectURL, nonce: p.nonce,
        tokenURL: tokenURL ?? p.tokenURL, clientID: clientID ?? p.clientID, createdAt: createdAt ?? p.createdAt
    )
}

@Suite("Pending authorization binding")
struct PendingBindingTests {
    @Test func crossProviderPendingIsRefused() async throws {
        // The reviewer's repro: a GitHub pending authorization completing a Facebook exchange.
        let transport = StubTransport()
            .on("https://github.com/login/oauth/access_token", #"{"access_token":"AT"}"#)
            .on("https://graph.facebook.com/v23.0/oauth/access_token", #"{"access_token":"FBAT"}"#)
        let github = GitHub(configuration: testConfiguration(transport: transport))
        let facebook = Facebook(configuration: testConfiguration(transport: transport, usePKCE: true))
        let request = try github.authorizationRequest()
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("created by a different provider or client")) {
            try await facebook.exchange(callback: callback(request), pending: request.pending)
        }
        let otherClient = OAuth2(
            configuration: OAuth2ClientConfiguration(clientID: "other", clientSecret: "s", redirectURL: request.pending.redirectURL, http: OAuth2HTTPOptions(transport: transport)),
            authorizationURL: github.oauth2.authorizationURL, tokenURL: github.oauth2.tokenURL
        )
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("created by a different provider or client")) {
            try await otherClient.exchange(callback: callback(request), pending: request.pending)
        }
        #expect(transport.requests.isEmpty)
    }

    @Test func tamperedRedirectIsRefused() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let oauth = client(transport)
        let request = try oauth.authorizationRequest()
        for redirect in ["http://evil.test/steal#frag", "https://app.test/auth/callback?x=1", "https://evil.test/auth/callback"] {
            await #expect(throws: OAuth2Error.invalidPendingAuthorization("redirect URL differs from the configured one")) {
                try await oauth.exchange(callback: callback(request), pending: copy(request.pending, redirect: URL(string: redirect)!))
            }
        }
        #expect(transport.requests.isEmpty)
    }

    @Test func junkOrMismatchedVerifierIsRefused() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let oauth = client(transport)
        let request = try oauth.authorizationRequest()
        for verifier in ["a b", "short", String(repeating: "a", count: 129), String(repeating: "a", count: 42) + "+"] {
            await #expect(throws: OAuth2Error.invalidPendingAuthorization("malformed code verifier")) {
                try await oauth.exchange(callback: callback(request), pending: copy(request.pending, verifier: .some(verifier)))
            }
        }
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("PKCE is enabled but there is no code verifier")) {
            try await oauth.exchange(callback: callback(request), pending: copy(request.pending, verifier: .some(nil)))
        }
        let noPKCE = client(transport, pkce: false)
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("PKCE is disabled but there is a code verifier")) {
            try await noPKCE.exchange(callback: callback(request), pending: request.pending)
        }
        #expect(transport.requests.isEmpty)
        #expect(PKCE.isValidVerifier(String(repeating: "a", count: 43)))
        #expect(PKCE.isValidVerifier(String(repeating: "-._~", count: 32)))
    }

    @Test func expiryAndFutureCreation() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let oauth = client(transport, maxAge: 60)
        let request = try oauth.authorizationRequest()
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("expired")) {
            try await oauth.exchange(callback: callback(request), pending: copy(request.pending, createdAt: Date().addingTimeInterval(-61)))
        }
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("created in the future")) {
            try await oauth.exchange(callback: callback(request), pending: copy(request.pending, createdAt: Date().addingTimeInterval(3600)))
        }
        _ = try await oauth.exchange(callback: callback(request), pending: copy(request.pending, createdAt: Date().addingTimeInterval(-59)))
    }

    @Test func reuseIsRefused() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let oauth = client(transport)
        let request = try oauth.authorizationRequest()
        _ = try await oauth.exchange(callback: callback(request, code: "c1"), pending: request.pending)
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("already used")) {
            try await oauth.exchange(callback: callback(request, code: "c2"), pending: request.pending)
        }
        #expect(transport.requests.count == 1)
        // A failed exchange consumes it too: the code was already sent.
        let failing = client(StubTransport().on(tokenURL, status: 400, #"{"error":"invalid_grant"}"#))
        let second = try failing.authorizationRequest()
        await #expect(throws: OAuth2Error.self) { try await failing.exchange(callback: callback(second), pending: second.pending) }
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("already used")) {
            try await failing.exchange(callback: callback(second), pending: second.pending)
        }
    }

    @Test func floodKeepsTheNewestHalf() {
        let states = CompletedStates()
        let now = Date()
        let total = CompletedStates.capacity + 10
        for index in 0..<total { _ = states.insert("s\(index)", now: now, maxAge: 600) }
        // The most recent states are still refused; the oldest were evicted (best-effort, documented).
        for index in (total - 1000)..<total { #expect(!states.insert("s\(index)", now: now, maxAge: 600)) }
        #expect(states.insert("s0", now: now, maxAge: 600))
    }

    @Test func completedStatesAgeOut() {
        let states = CompletedStates()
        let start = Date()
        #expect(states.insert("a", now: start, maxAge: 10))
        #expect(!states.insert("a", now: start.addingTimeInterval(5), maxAge: 10))
        #expect(states.insert("a", now: start.addingTimeInterval(11), maxAge: 10))
    }

    @Test func oversizedCodeIsRefused() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let oauth = client(transport, pkce: false)
        let request = try oauth.authorizationRequest()
        await #expect(throws: OAuth2Error.invalidCallback("code longer than 4096 bytes")) {
            try await oauth.exchange(callback: callback(request, code: String(repeating: "C", count: 4097)), pending: request.pending)
        }
        #expect(transport.requests.isEmpty)
    }
}

@Suite("Token type and sanitizer")
struct TokenTypeSanitizerTests {
    @Test func onlyBearerIsAccepted() async throws {
        for (body, ok) in [(#"{"access_token":"a","token_type":"mac"}"#, false), (#"{"access_token":"a","token_type":"DPoP"}"#, false),
                           (#"{"access_token":"a","token_type":"BEARER"}"#, true), (#"{"access_token":"a","token_type":"bearer"}"#, true),
                           (#"{"access_token":"a"}"#, true)] {
            let oauth = client(StubTransport().on(tokenURL, body))
            if ok {
                _ = try await oauth.refresh(refreshToken: "r")
            } else {
                await #expect(throws: OAuth2Error.invalidResponse("unsupported token_type")) { try await oauth.refresh(refreshToken: "r") }
            }
        }
    }

    @Test func shortAndEncodedSecretsAreRedacted() async {
        // The reviewer's repro: a 7-character client secret echoed raw, and an encoded secret.
        let body = #"{"error":"invalid_client","error_description":"secret abc1234 / abc1234 enc s3cr3t%2F%2B%3D%26 lower s3cr3t%2f%2b%3d%26 refresh R-TOKEN-1234567 R-TOKEN%2D1234567"}"#
        for secret in ["abc1234", "s3cr3t/+=&"] {
            let oauth = client(StubTransport().on(tokenURL, status: 400, body), secret: secret)
            let error = await #expect(throws: OAuth2Error.self) { try await oauth.refresh(refreshToken: "R-TOKEN-1234567") }
            let text = String(describing: error)
            #expect(!text.contains(secret))
            #expect(!text.contains(percentEncodeAll(secret)))
            #expect(!text.lowercased().contains(percentEncodeAll(secret).lowercased()) || !percentEncodeAll(secret).contains("%"))
            #expect(!text.contains("R-TOKEN-1234567"))
        }
        // Ordinary words survive short non-secret values.
        let words = OAuth2ErrorResponse(code: "x", errorDescription: "the code was revoked", errorURI: nil, redacting: ["", "revoked"], alwaysRedact: 1)
        #expect(words.errorDescription == "the code was revoked")
    }
}

@Suite("Redaction and parsing nits")
struct NitTests {
    @Test func repeatedErrorParameterIsAnError() {
        let callback = AuthorizationCallback(url: URL(string: "https://app.test/cb?error=a&error=b&code=c&state=s")!)
        #expect(callback.error?.code == "invalid_request")
    }

    @Test func profileMirrorShowsRawKeysOnly() throws {
        let profile = try OAuthUserProfile(userid: "u", loginType: "t", token: OAuth2Token(accessToken: "a"),
                                           raw: .object(["access_token": .string("RAW-ACCESS-IN-RAW")]))
        var text = ""
        dump(profile, to: &text)
        #expect(!text.contains("RAW-ACCESS-IN-RAW"))
        #expect(text.contains("access_token"))
    }

    @Test func callbackAndRequestRedaction() throws {
        let request = try client(StubTransport()).authorizationRequest()
        let callback = AuthorizationCallback(code: "AUTH-CODE-VALUE", state: request.pending.state)
        for value in [callback as Any, request as Any] {
            var text = "\(value) \(String(reflecting: value))"
            dump(value, to: &text)
            for secret in ["AUTH-CODE-VALUE", request.pending.state, request.pending.codeVerifier!, "code_challenge"] {
                #expect(!text.contains(secret), "\(secret) leaked")
            }
        }
    }

    @Test func loopbackIsExact() {
        for (url, ok) in [("http://localhost/a", true), ("http://127.0.0.1:8080/a", true), ("http://[::1]:8080/a", true), ("http://LOCALHOST/a", true),
                          ("http://evil.localhost/a", false), ("http://localhost.evil.test/a", false), ("http://127.0.0.2/a", false),
                          ("http://0.0.0.0/a", false), ("http://127.0.0.1.nip.io/a", false), ("https://x.test/a", true),
                          ("https:x.test", false)] {
            #expect(((try? requireSecure(URL(string: url)!, "x")) != nil) == ok, "\(url)")
        }
    }

    @Test func salesforceIdentitySuffixesAreConfigurable() throws {
        let configuration = testConfiguration(transport: StubTransport())
        let salesforce = try Salesforce(configuration: configuration, identityHostSuffixes: [".example-cloud.test"])
        #expect(salesforce.isSalesforceHost("id.example-cloud.test"))
        #expect(!salesforce.isSalesforceHost("login.salesforce.com.evil.test"))
        #expect(salesforce.isSalesforceHost("login.salesforce.com"))  // the login host is always allowed
        #expect(throws: OAuth2Error.self) { try Salesforce(configuration: configuration, identityHostSuffixes: ["salesforce.com"]) }
        #expect(try Salesforce(configuration: configuration).identityHostSuffixes == [".salesforce.com", ".salesforce.mil"])
    }

    @Test func idTokenShapes() {
        let now = Int(Date().timeIntervalSince1970)
        let claims: [String: Any] = ["iss": "https://accounts.google.com", "aud": "c", "sub": "1", "exp": now + 600, "iat": now]
        let header = base64URLEncode(Data(#"{"alg":"none"}"#.utf8))
        let body = base64URLEncode(try! JSONSerialization.data(withJSONObject: claims))
        // alg is irrelevant: the signature isn't checked and the token is only trusted from the token
        // endpoint. Segment count still is.
        #expect((try? IDTokenClaims.validate("\(header).\(body).", issuers: Google.issuers, clientID: "c")) != nil)
        for token in ["\(header).\(body)", "\(header).\(body).x.y", "a.b.c.d.e"] {
            #expect(throws: OAuth2Error.invalidIDToken("not a compact JWS")) {
                try IDTokenClaims.validate(token, issuers: Google.issuers, clientID: "c")
            }
        }
    }
}

extension TransportSuites {
    @Suite("Transport hardening", .serialized)
    struct TransportHardeningTests {
        private func oauth(_ kind: TransportKind, _ server: LocalHTTPServer, timeout: TimeInterval = 10) -> OAuth2 {
            OAuth2(
                configuration: OAuth2ClientConfiguration(clientID: "id", clientSecret: "s", redirectURL: URL(string: "https://app.test/cb")!, usePKCE: false,
                                                         http: OAuth2HTTPOptions(timeout: timeout, transport: kind.make(timeout: timeout, limit: 1 << 20))),
                authorizationURL: URL(string: "https://auth.test/a")!, tokenURL: URL(string: "\(server.baseURL)/token")!
            )
        }

        @Test(arguments: TransportKind.allCases) func compressedResponsesAreRefusedAndIdentityRequested(kind: TransportKind) async throws {
            // A real gzip stream of 1 MiB of spaces (about 1 KB compressed); never decompressed.
            let gzip = try #require(Data(base64Encoded: gzippedSpacesBase64))
            for encoding in ["gzip", "br", "deflate", " GZIP "] {
                let server = try LocalHTTPServer { _ in
                    .raw(head: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: \(encoding)\r\nContent-Length: \(gzip.count)\r\nConnection: close\r\n\r\n", chunk: gzip, count: 1)
                }
                defer { server.stop() }
                let error = await #expect(throws: OAuth2Error.self) { try await oauth(kind, server).refresh(refreshToken: "r") }
                guard case .invalidResponse(let why)? = error else { Issue.record("\(String(describing: error))"); continue }
                #expect(why.hasPrefix("compressed response refused"))
                let head = try #require(server.requests.first?.head.lowercased())
                #expect(head.contains("accept-encoding: identity"))
            }
            let identity = try LocalHTTPServer { _ in
                .respond(status: 200, headers: ["Content-Encoding": "identity"], body: Data(#"{"access_token":"AT"}"#.utf8))
            }
            defer { identity.stop() }
            #expect(try await oauth(kind, identity).refresh(refreshToken: "r").accessToken == "AT")
        }

        @Test(arguments: TransportKind.allCases) func infiniteTimeoutDoesNotTrap(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .respond(status: 200, headers: [:], body: Data(#"{"access_token":"AT"}"#.utf8)) }
            defer { server.stop() }
            for timeout in [TimeInterval.infinity, .greatestFiniteMagnitude, .nan] {
                _ = await Result(catching: { try await oauth(kind, server, timeout: timeout).refresh(refreshToken: "r") })
            }
        }

        @Test(arguments: TransportKind.allCases) func alreadyCancelledTaskSendsNothing(kind: TransportKind) async throws {
            let server = try LocalHTTPServer { _ in .respond(status: 200, headers: [:], body: Data(#"{"access_token":"AT"}"#.utf8)) }
            defer { server.stop() }
            let client = oauth(kind, server)
            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                return try await client.refresh(refreshToken: "r")
            }
            if case .success = await task.result { Issue.record("cancelled request succeeded") }
            try await Task.sleep(nanoseconds: 300_000_000)
            #expect(server.requests.isEmpty)
        }
    }
}

extension Result where Failure == any Error {
    init(catching body: () async throws -> Success) async {
        do { self = .success(try await body()) } catch { self = .failure(error) }
    }
}

/// gzip of 1 MiB of spaces (generated with Python's gzip module).
private let gzippedSpacesBase64 = "H4sIADCW3moC/+3BMQEAAADCoCrrn9IQvkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHwGpwID8QAAEAA="

@Suite("Provider hook compatibility and ordering")
struct HookCompatibilityTests {
    /// A conformer written against the pre-release API: it implements only `validate(_:)`.
    struct LegacyProvider: OAuth2Provider {
        let oauth2: OAuth2
        let loginType = "legacy"
        func validate(_ token: OAuth2Token) throws { throw OAuth2Error.invalidResponse("legacy validate ran") }
        func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
            try OAuthUserProfile(userid: "u", loginType: loginType, token: token)
        }
    }

    @Test func legacyValidateStillRuns() async throws {
        let transport = StubTransport().on(tokenURL, #"{"access_token":"AT"}"#)
        let provider = LegacyProvider(oauth2: client(transport))
        let request = try provider.authorizationRequest()
        await #expect(throws: OAuth2Error.invalidResponse("legacy validate ran")) {
            try await provider.completeAuthorization(callback: callback(request), pending: request.pending)
        }
    }

    @Test func pendingIsCheckedBeforeAnErrorCallback() async throws {
        let oauth = client(StubTransport(), maxAge: 60)
        let request = try oauth.authorizationRequest()
        let expired = copy(request.pending, createdAt: Date().addingTimeInterval(-120))
        let denied = AuthorizationCallback(code: nil, state: request.pending.state, error: OAuth2ErrorResponse(code: "access_denied"))
        await #expect(throws: OAuth2Error.invalidPendingAuthorization("expired")) {
            try await oauth.exchange(callback: denied, pending: expired)
        }
        await #expect(throws: OAuth2Error.authorizationDenied(OAuth2ErrorResponse(code: "access_denied"))) {
            try await oauth.exchange(callback: denied, pending: request.pending)
        }
    }
}
