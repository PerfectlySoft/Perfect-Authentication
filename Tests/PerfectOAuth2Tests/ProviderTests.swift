import Foundation
import Testing
@testable import PerfectOAuth2

/// Runs a full sign-in against canned responses and returns the profile and the transport.
private func signIn<P: OAuth2Provider>(
    _ make: (OAuth2ClientConfiguration) throws -> P,
    token: (url: String, body: String),
    profile: (url: String, status: Int, body: String)?,
    scopes: [String]? = nil
) async throws -> (OAuthUserProfile, StubTransport, AuthorizationRequest) {
    let transport = StubTransport().on(token.url, token.body)
    if let profile { transport.on(profile.url, status: profile.status, profile.body) }
    let provider = try make(testConfiguration(transport: transport, scopes: scopes))
    let request = try provider.authorizationRequest()
    let callback = URL(string: "https://app.test/auth/callback?code=CODE&state=\(request.pending.state)")!
    let result = try await provider.completeAuthorization(callbackURL: callback, pending: request.pending)
    return (result, transport, request)
}

private func assertBearer(_ request: OAuth2HTTPRequest?, _ token: String = "AT") {
    #expect(request?.headers["Authorization"] == "Bearer \(token)")
    #expect(request?.url.absoluteString.contains(token) == false)
    #expect(request?.method == .get)
}

private let now = Date().timeIntervalSince1970

private func googleIDToken(_ overrides: [String: Any] = [:], removing: [String] = []) -> String {
    var claims: [String: Any] = [
        "iss": "https://accounts.google.com", "aud": "client id&x", "sub": "1234567890",
        "exp": now + 3600, "iat": now, "hd": "corp.test", "email": "a@corp.test", "email_verified": true,
    ]
    claims.merge(overrides) { _, new in new }
    for key in removing { claims.removeValue(forKey: key) }
    return makeJWT(claims)
}

private let googleToken = "https://oauth2.googleapis.com/token"
private let googleUserInfo = "https://openidconnect.googleapis.com/v1/userinfo"

@Suite("Google")
struct GoogleTests {
    @Test func loginLink() throws {
        let google = Google(configuration: testConfiguration(transport: StubTransport()), restrictedDomain: "Corp.Test&prompt=none")
        let request = try google.authorizationRequest()
        let query = try #require(queryParameters(request.url))
        #expect(request.url.host == "accounts.google.com")
        #expect(request.url.path == "/o/oauth2/v2/auth")
        #expect(query["scope"] == "openid profile")
        #expect(query["hd"] == "corp.test&prompt=none")  // one encoded value, not an injected prompt
        #expect(query["prompt"] == nil)
        #expect(query["code_challenge_method"] == "S256")
        #expect(query["access_type"] == nil)
    }

    @Test func offlineAccessAndOpenIDAlwaysRequested() throws {
        let google = Google(configuration: testConfiguration(transport: StubTransport(), scopes: ["email"]))
        let query = try #require(queryParameters(try google.authorizationRequest(offlineAccess: true).url))
        #expect(query["access_type"] == "offline")
        #expect(query["prompt"] == "consent")
        #expect(query["scope"] == "openid email")
        let custom = try #require(queryParameters(try google.authorizationRequest(scopes: ["profile"], offlineAccess: false).url))
        #expect(custom["scope"] == "openid profile")
        #expect(custom["access_type"] == nil)
    }

    @Test func signInUsesBearerHeaderAndValidatedIDToken() async throws {
        let (profile, transport, request) = try await signIn(
            { Google(configuration: $0, restrictedDomain: "corp.test") },
            token: (googleToken, #"{"access_token":"AT","id_token":"\#(googleIDToken())","expires_in":3599}"#),
            profile: (googleUserInfo, 200, #"{"sub":"1234567890","given_name":"Ada","family_name":"Lovelace","name":"Ada Lovelace","picture":"https://p.test/a.png","email":"a@corp.test","email_verified":true,"hd":"corp.test"}"#)
        )
        #expect(profile.userid == "1234567890")
        #expect(profile.firstName == "Ada")
        #expect(profile.lastName == "Lovelace")
        #expect(profile.email == "a@corp.test")
        #expect(profile.emailVerified)
        #expect(profile.loginType == "google")
        assertBearer(transport.requests(to: googleUserInfo).first)
        let fields = formFields(transport.requests(to: googleToken).first?.body)
        #expect(fields["code"] == "CODE")
        #expect(fields["code_verifier"] == request.pending.codeVerifier)
        #expect(fields["redirect_uri"] == "https://app.test/auth/callback")
    }

    @Test func emptyUserIDFromUserInfoIsRejected() async throws {
        // 1.x returned a profile with userid "" here.
        for body in [#"{}"#, #"{"sub":""}"#, #"{"id":"legacy-field"}"#] {
            await #expect(throws: OAuth2Error.missingUserID) {
                _ = try await signIn({ Google(configuration: $0) }, token: (googleToken, #"{"access_token":"AT"}"#), profile: (googleUserInfo, 200, body))
            }
        }
        await #expect(throws: OAuth2Error.httpStatus(500)) {
            _ = try await signIn({ Google(configuration: $0) }, token: (googleToken, #"{"access_token":"AT"}"#), profile: (googleUserInfo, 500, "oops"))
        }
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "invalid_token"))) {
            _ = try await signIn({ Google(configuration: $0) }, token: (googleToken, #"{"access_token":"AT"}"#), profile: (googleUserInfo, 401, #"{"error":"invalid_token"}"#))
        }
    }

    @Test func idTokenChecks() async throws {
        let cases: [(String, OAuth2Error)] = [
            (googleIDToken(["iss": "https://evil.test"]), .invalidIDToken("unexpected issuer")),
            (googleIDToken(["aud": "someone-else"]), .invalidIDToken("audience is not this client")),
            (googleIDToken(["aud": ["client id&x", "other"]]), .invalidIDToken("authorized party is not this client")),
            (googleIDToken(["exp": now - 600]), .invalidIDToken("expired")),
            (googleIDToken(removing: ["exp"]), .invalidIDToken("no expiry")),
            (googleIDToken(["iat": now + 3600]), .invalidIDToken("issued in the future")),
            (googleIDToken(["sub": ""]), .invalidIDToken("no subject")),
            (googleIDToken(["hd": "other.test"]), .restrictedDomainMismatch),
            (googleIDToken(removing: ["hd"]), .restrictedDomainMismatch),
            ("not.a-jwt", .invalidIDToken("not a compact JWS")),
            ("a.b+/=.c", .invalidIDToken("payload is not base64url JSON")),
        ]
        for (idToken, expected) in cases {
            await #expect(throws: expected) {
                _ = try await signIn(
                    { Google(configuration: $0, restrictedDomain: "corp.test") },
                    token: (googleToken, #"{"access_token":"AT","id_token":"\#(idToken)"}"#),
                    profile: (googleUserInfo, 200, #"{"sub":"1234567890"}"#)
                )
            }
        }
        // Restricted domain without an id_token at all.
        await #expect(throws: OAuth2Error.invalidIDToken("no id_token; request the openid scope")) {
            _ = try await signIn({ Google(configuration: $0, restrictedDomain: "corp.test") }, token: (googleToken, #"{"access_token":"AT"}"#), profile: nil)
        }
        // Accepted: azp matches with multiple audiences, issuer without scheme, small clock skew.
        _ = try await signIn(
            { Google(configuration: $0, restrictedDomain: "CORP.test") },
            token: (googleToken, #"{"access_token":"AT","id_token":"\#(googleIDToken(["aud": ["client id&x", "other"], "azp": "client id&x", "iss": "accounts.google.com", "exp": now - 60]))"}"#),
            profile: (googleUserInfo, 200, #"{"sub":"1234567890"}"#)
        )
    }

    @Test func base64URLIDTokenPayloadDecodes() async throws {
        // A payload whose base64url form contains '-' and '_' (1.x used standard base64 and failed).
        let token = googleIDToken(["name": "??>>~~ÿ"])
        #expect(token.split(separator: ".")[1].contains { $0 == "-" || $0 == "_" })
        let claims = try IDTokenClaims.validate(token, issuers: Google.issuers, clientID: "client id&x")
        #expect(claims.claims["hd"]?.stringValue == "corp.test")
    }

    @Test func subjectMismatchBetweenIDTokenAndUserInfo() async {
        await #expect(throws: OAuth2Error.invalidResponse("userinfo subject differs from the id_token subject")) {
            _ = try await signIn({ Google(configuration: $0) },
                token: (googleToken, #"{"access_token":"AT","id_token":"\#(googleIDToken())"}"#),
                profile: (googleUserInfo, 200, #"{"sub":"someone-else"}"#))
        }
    }
}

@Suite("GitHub")
struct GitHubTests {
    @Test func loginLinkAndSignIn() async throws {
        let (profile, transport, request) = try await signIn(
            { GitHub(configuration: $0) },
            token: ("https://github.com/login/oauth/access_token", #"{"access_token":"AT","token_type":"bearer","scope":"read:user"}"#),
            profile: ("https://api.github.com/user", 200, #"{"id":5833,"login":"octo","name":"Mona Lisa Octocat","avatar_url":"https://a.test/o.png","email":"m@x.test"}"#)
        )
        let query = try #require(queryParameters(request.url))
        #expect(request.url.absoluteString.hasPrefix("https://github.com/login/oauth/authorize?"))
        #expect(query["scope"] == "read:user")
        #expect(query["code_challenge"] != nil)
        #expect(profile.userid == "5833")
        #expect(profile.firstName == "Mona")
        #expect(profile.lastName == "Octocat")
        #expect(profile.displayName == "Mona Lisa Octocat")
        #expect(profile.email == "m@x.test")
        #expect(!profile.emailVerified)
        let userRequest = transport.requests(to: "https://api.github.com/user").first
        assertBearer(userRequest)
        #expect(userRequest?.headers["User-Agent"] == "PerfectOAuth2/2.0")
        #expect(userRequest?.headers["Accept"] == "application/vnd.github+json")
    }

    @Test func http200ErrorAndMissingID() async {
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "bad_verification_code"))) {
            _ = try await signIn({ GitHub(configuration: $0) }, token: ("https://github.com/login/oauth/access_token", #"{"error":"bad_verification_code"}"#), profile: nil)
        }
        await #expect(throws: OAuth2Error.missingUserID) {
            _ = try await signIn({ GitHub(configuration: $0) }, token: ("https://github.com/login/oauth/access_token", #"{"access_token":"AT"}"#), profile: ("https://api.github.com/user", 200, #"{"login":"octo","id":null}"#))
        }
    }
}

@Suite("Facebook")
struct FacebookTests {
    @Test func loginLinkAndSignIn() async throws {
        let (profile, transport, request) = try await signIn(
            { Facebook(configuration: $0) },
            token: ("https://graph.facebook.com/v23.0/oauth/access_token", #"{"access_token":"AT","token_type":"bearer","expires_in":5183944}"#),
            profile: ("https://graph.facebook.com/v23.0/me", 200, #"{"id":"10153","name":"Ada L","first_name":"Ada","last_name":"L","picture":{"data":{"url":"https://p.test/a.jpg","height":50}}}"#)
        )
        let query = try #require(queryParameters(request.url))
        #expect(request.url.absoluteString.hasPrefix("https://www.facebook.com/v23.0/dialog/oauth?"))
        #expect(query["code_challenge"] == nil)  // PKCE off by default
        #expect(query["scope"] == nil)
        #expect(profile.userid == "10153")
        #expect(profile.picture == "https://p.test/a.jpg")
        let me = try #require(transport.requests(to: "https://graph.facebook.com/v23.0/me").first)
        assertBearer(me)
        let meQuery = try #require(queryParameters(me.url))
        #expect(meQuery["access_token"] == nil)
        #expect(meQuery["fields"] == "id,name,first_name,last_name,picture")
        #expect(meQuery["appsecret_proof"] == Facebook.appSecretProof(accessToken: "AT", appSecret: "s3cr3t/+=&"))
        #expect(formFields(transport.requests(to: "https://graph.facebook.com/v23.0/oauth/access_token").first?.body)["code_verifier"] == nil)
    }

    @Test func graphErrorObject() async {
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "OAuthException", errorDescription: "Invalid OAuth access token."))) {
            _ = try await signIn({ Facebook(configuration: $0) },
                token: ("https://graph.facebook.com/v23.0/oauth/access_token", #"{"access_token":"AT"}"#),
                profile: ("https://graph.facebook.com/v23.0/me", 400, #"{"error":{"message":"Invalid OAuth access token.","type":"OAuthException","code":190}}"#))
        }
    }

    @Test func graphVersionIsConfigurable() throws {
        let facebook = Facebook(configuration: testConfiguration(transport: StubTransport()), graphAPIVersion: "v24.0")
        #expect(try facebook.authorizationRequest().url.path == "/v24.0/dialog/oauth")
        #expect(facebook.oauth2.tokenURL.absoluteString == "https://graph.facebook.com/v24.0/oauth/access_token")
        for bad in ["", "v1/../x", "vé", "v1?x"] {
            #expect(Facebook(configuration: testConfiguration(transport: StubTransport()), graphAPIVersion: bad).graphAPIVersion == "v23.0")
        }
    }
}

@Suite("LinkedIn")
struct LinkedInTests {
    @Test func loginLinkAndSignIn() async throws {
        let (profile, transport, request) = try await signIn(
            { LinkedIn(configuration: $0) },
            token: ("https://www.linkedin.com/oauth/v2/accessToken", #"{"access_token":"AT","expires_in":5184000,"scope":"openid,profile"}"#),
            profile: ("https://api.linkedin.com/v2/userinfo", 200, #"{"sub":"782bbtaQ","name":"Ada L","given_name":"Ada","family_name":"L","picture":"https://p.test/l.jpg","email":"a@x.test","email_verified":true}"#),
            scopes: ["openid", "profile", "email"]
        )
        let query = try #require(queryParameters(request.url))
        #expect(query["scope"] == "openid profile email")
        #expect(query["code_challenge"] == nil)
        #expect(profile.userid == "782bbtaQ")
        #expect(profile.emailVerified)
        #expect(profile.token.scope == ["openid", "profile"])
        assertBearer(transport.requests(to: "https://api.linkedin.com/v2/userinfo").first)
    }

    @Test func defaultScopes() throws {
        let request = try LinkedIn(configuration: testConfiguration(transport: StubTransport())).authorizationRequest()
        #expect(queryParameters(request.url)?["scope"] == "openid profile")
    }
}

@Suite("Salesforce")
struct SalesforceTests {
    private let idURL = "https://login.salesforce.com/id/00Dx0000000BV7z/005x00000012Q9P"

    @Test func loginLinkAndSignIn() async throws {
        let (profile, transport, request) = try await signIn(
            { try Salesforce(configuration: $0) },
            token: ("https://login.salesforce.com/services/oauth2/token", #"{"access_token":"AT","instance_url":"https://na1.salesforce.com","id":"\#(idURL)","token_type":"Bearer","issued_at":"1278448101416"}"#),
            profile: (idURL, 200, #"{"user_id":"005x00000012Q9P","first_name":"Ada","last_name":"L","display_name":"Ada L","photos":{"picture":"https://p.test/s.png"},"email":"a@x.test","email_verified":true}"#)
        )
        #expect(queryParameters(request.url)?["scope"] == "id")
        #expect(queryParameters(request.url)?["code_challenge"] != nil)
        #expect(profile.userid == "005x00000012Q9P")
        #expect(profile.picture == "https://p.test/s.png")
        #expect(profile.token.instanceURL == "https://na1.salesforce.com")
        assertBearer(transport.requests(to: idURL).first)
        #expect(formFields(transport.requests(to: "https://login.salesforce.com/services/oauth2/token").first?.body)["code_verifier"] == request.pending.codeVerifier)
    }

    @Test func identityURLMustBeSalesforceHTTPS() async {
        for bad in ["http://login.salesforce.com/id/1/2", "https://evil.test/id/1/2", "https://salesforce.com.evil.test/id", "https://x.force.com/id/1/2"] {
            await #expect(throws: OAuth2Error.insecureURL("identity URL is not an https Salesforce URL")) {
                _ = try await signIn({ try Salesforce(configuration: $0) }, token: ("https://login.salesforce.com/services/oauth2/token", #"{"access_token":"AT","id":"\#(bad)"}"#), profile: nil)
            }
        }
        await #expect(throws: OAuth2Error.invalidResponse("token response has no identity URL (id)")) {
            _ = try await signIn({ try Salesforce(configuration: $0) }, token: ("https://login.salesforce.com/services/oauth2/token", #"{"access_token":"AT"}"#), profile: nil)
        }
    }

    @Test func sandboxHost() throws {
        let salesforce = try Salesforce(configuration: testConfiguration(transport: StubTransport()), loginHost: "test.salesforce.com")
        #expect(try salesforce.authorizationRequest().url.host == "test.salesforce.com")
        #expect(throws: OAuth2Error.self) {
            try Salesforce(configuration: testConfiguration(transport: StubTransport()), loginHost: "evil.test/x?")
        }
        #expect(throws: OAuth2Error.self) {
            try Salesforce(configuration: testConfiguration(transport: StubTransport()), loginHost: "tést.salesforce.com")
        }
    }
}

@Suite("Slack")
struct SlackTests {
    @Test func loginLinkAndSignIn() async throws {
        let (profile, transport, request) = try await signIn(
            { Slack(configuration: $0) },
            token: ("https://slack.com/api/openid.connect.token", #"{"ok":true,"access_token":"xoxp-AT","token_type":"Bearer","id_token":"x.y.z"}"#),
            profile: ("https://slack.com/api/openid.connect.userInfo", 200, #"{"ok":true,"sub":"U0R7JM","https://slack.com/user_id":"U0R7JM","https://slack.com/team_id":"T0R7GR","name":"Ada L","given_name":"Ada","family_name":"L","picture":"https://p.test/s.png"}"#)
        )
        #expect(request.url.absoluteString.hasPrefix("https://slack.com/openid/connect/authorize?"))
        #expect(queryParameters(request.url)?["scope"] == "openid profile")
        #expect(queryParameters(request.url)?["code_challenge"] == nil)
        #expect(profile.userid == "U0R7JM")
        #expect(profile.raw["https://slack.com/team_id"]?.stringValue == "T0R7GR")
        assertBearer(transport.requests(to: "https://slack.com/api/openid.connect.userInfo").first, "xoxp-AT")
    }

    @Test func okFalseIsAnError() async {
        await #expect(throws: OAuth2Error.providerError(OAuth2ErrorResponse(code: "invalid_auth"))) {
            _ = try await signIn({ Slack(configuration: $0) },
                token: ("https://slack.com/api/openid.connect.token", #"{"ok":true,"access_token":"AT"}"#),
                profile: ("https://slack.com/api/openid.connect.userInfo", 200, #"{"ok":false,"error":"invalid_auth"}"#))
        }
    }
}

@Suite("Custom providers")
struct CustomProviderTests {
    struct Gitea: OAuth2Provider {
        let oauth2: OAuth2
        let loginType = "gitea"
        init(configuration: OAuth2ClientConfiguration) {
            oauth2 = OAuth2(
                configuration: configuration,
                authorizationURL: URL(string: "https://gitea.test/login/oauth/authorize")!,
                tokenURL: URL(string: "https://gitea.test/login/oauth/access_token")!,
                defaultScopes: ["read:user"]
            )
        }
        func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
            let user = try await oauth2.getJSON(URL(string: "https://gitea.test/api/v1/user")!, accessToken: token.accessToken)
            return try OAuthUserProfile(userid: user["id"]?.identifierValue, loginType: loginType, token: token, raw: user)
        }
    }

    @Test func conformingTypeGetsTheWholeFlow() async throws {
        let (profile, _, _) = try await signIn(
            { Gitea(configuration: $0) },
            token: ("https://gitea.test/login/oauth/access_token", #"{"access_token":"AT"}"#),
            profile: ("https://gitea.test/api/v1/user", 200, #"{"id":7}"#)
        )
        #expect(profile.userid == "7")
        #expect(profile.loginType == "gitea")
    }
}
