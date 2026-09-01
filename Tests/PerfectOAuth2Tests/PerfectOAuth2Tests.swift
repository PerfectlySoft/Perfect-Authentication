import Testing
@testable import PerfectOAuth2

@Suite("OAuth2 Core", .serialized)
struct OAuth2CoreTests {

    @Test func urlEncodeBasic() {
        #expect("hello world".urlEncoded == "hello%20world")
    }

    @Test func urlEncodeSpecialChars() {
        let raw = "https://app.com/callback?session=abc"
        let encoded = raw.urlEncoded
        #expect(encoded.contains("%3A"))  // : encoded
        #expect(encoded.contains("%2F"))  // / encoded
        #expect(encoded.contains("%3F"))  // ? encoded
        #expect(encoded.contains("%3D"))  // = encoded
    }

    @Test func urlencodeDict() {
        let encoded = urlencode(dict: ["grant_type": "authorization_code", "code": "abc"])
        #expect(encoded.contains("grant_type=authorization_code"))
        #expect(encoded.contains("code=abc"))
        #expect(encoded.contains("&"))
    }

    @Test func loginLinkStructure() {
        let oauth = OAuth2(
            clientID: "test_id",
            clientSecret: "test_secret",
            authorizationURL: "https://auth.example.com/oauth",
            tokenURL: "https://auth.example.com/token"
        )
        let link = oauth.getLoginLink(redirectURL: "https://myapp.com/cb", state: "abc", scopes: ["profile"])
        #expect(link.hasPrefix("https://auth.example.com/oauth?response_type=code"))
        #expect(link.contains("client_id=test_id"))
        #expect(link.contains("state=abc"))
        #expect(link.contains("scope=profile"))
        #expect(link.contains("redirect_uri="))
    }

    @Test func loginLinkEncodesRedirectURI() {
        let oauth = OAuth2(
            clientID: "id",
            clientSecret: "secret",
            authorizationURL: "https://auth.example.com/oauth",
            tokenURL: "https://auth.example.com/token"
        )
        let link = oauth.getLoginLink(redirectURL: "https://app.com/cb?session=tok", state: "s")
        #expect(link.contains("redirect_uri=https%3A%2F%2Fapp.com%2Fcb%3Fsession%3Dtok"))
    }

    @Test func authorizationCodeInit() {
        let code = AuthorizationCode(code: "auth123", redirectURL: "https://app.com/callback")
        #expect(code.code == "auth123")
        #expect(code.redirectURL == "https://app.com/callback")
    }

    @Test func oauth2ErrorFromJSON() {
        let json: [String: Any] = ["error": "invalid_client", "error_description": "Client not found"]
        let error = OAuth2Error(json: json)
        #expect(error != nil)
        #expect(error?.code == .invalidClient)
        #expect(error?.description == "Client not found")
    }

    @Test func oauth2ErrorInvalidJSONReturnsNil() {
        let json: [String: Any] = ["message": "not_an_error"]
        #expect(OAuth2Error(json: json) == nil)
    }

    @Test func oauth2ErrorUnknownCodeReturnsNil() {
        let json: [String: Any] = ["error": "made_up_error"]
        #expect(OAuth2Error(json: json) == nil)
    }

    @Test func oauth2TokenFromJSON() {
        let json: [String: Any] = [
            "access_token": "ya29.token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "1//refresh",
            "scope": "profile email",
        ]
        let token = OAuth2Token(json: json)
        #expect(token != nil)
        #expect(token?.accessToken == "ya29.token")
        #expect(token?.tokenType == "Bearer")
        #expect(token?.refreshToken == "1//refresh")
        #expect(token?.scope == ["profile", "email"])
        #expect(token?.expiration != nil)
    }

    @Test func oauth2TokenNilWithoutAccessToken() {
        let json: [String: Any] = ["token_type": "Bearer"]
        #expect(OAuth2Token(json: json) == nil)
    }

    @Test func oauth2TokenDefaultsBearerType() {
        let json: [String: Any] = ["access_token": "tok"]
        let token = OAuth2Token(json: json)
        #expect(token?.tokenType == "Bearer")
    }

    @Test func oauthUserProfileInit() {
        let profile = OAuthUserProfile(
            userid: "12345",
            firstName: "Jane",
            lastName: "Doe",
            picture: "https://example.com/pic.jpg",
            accessToken: "tok",
            refreshToken: "refresh",
            loginType: "google"
        )
        #expect(profile.userid == "12345")
        #expect(profile.firstName == "Jane")
        #expect(profile.lastName == "Doe")
        #expect(profile.loginType == "google")
        #expect(profile.refreshToken == "refresh")
    }

    @Test func oauthUserProfileOptionalFields() {
        let profile = OAuthUserProfile(userid: "1", accessToken: "tok", loginType: "github")
        #expect(profile.firstName == nil)
        #expect(profile.picture == nil)
        #expect(profile.refreshToken == nil)
    }

    @Test func digIntoDictionaryNestedLookup() {
        let data: [String: Any] = [
            "picture": ["data": ["url": "https://example.com/photo.jpg"]]
        ]
        let result = digIntoDictionary(mineFor: ["picture", "data", "url"], data: data)
        #expect(result as? String == "https://example.com/photo.jpg")
    }

    @Test func digIntoDictionaryMissingKeyReturnsEmpty() {
        let data: [String: Any] = ["other": "value"]
        let result = digIntoDictionary(mineFor: ["picture", "data", "url"], data: data)
        #expect(result as? String == "")
    }

    @Test func digIntoDictionaryEmptyKeysReturnsEmpty() {
        let data: [String: Any] = ["key": "value"]
        let result = digIntoDictionary(mineFor: [], data: data)
        #expect(result as? String == "")
    }
}

@Suite("Provider URL Construction", .serialized)
struct ProviderURLTests {

    @Test func googleLoginURLContainsExpectedParams() {
        GoogleConfig.appid = "google_id"
        GoogleConfig.secret = "google_secret"
        GoogleConfig.endpointAfterAuth = "https://myapp.com/auth/google"
        GoogleConfig.restrictedDomain = nil
        let g = Google(clientID: "google_id", clientSecret: "google_secret")
        let url = g.loginURL(state: "csrf123", sessionToken: "sess456")
        #expect(url.contains("accounts.google.com"))
        #expect(url.contains("response_type=code"))
        #expect(url.contains("state=csrf123"))
        #expect(url.contains("scope=profile"))
        #expect(!url.contains("hd="))
    }

    @Test func googleLoginURLIncludesHdWhenRestricted() {
        GoogleConfig.appid = "google_id"
        GoogleConfig.secret = "google_secret"
        GoogleConfig.endpointAfterAuth = "https://myapp.com/auth/google"
        GoogleConfig.restrictedDomain = "mycompany.com"
        let g = Google(clientID: "google_id", clientSecret: "google_secret")
        let url = g.loginURL(state: "state", sessionToken: "tok")
        #expect(url.contains("hd=mycompany.com"))
        GoogleConfig.restrictedDomain = nil
    }

    @Test func githubLoginURLContainsExpectedParams() {
        GitHubConfig.appid = "gh_id"
        GitHubConfig.secret = "gh_secret"
        GitHubConfig.endpointAfterAuth = "https://myapp.com/auth/github"
        let g = GitHub(clientID: "gh_id", clientSecret: "gh_secret")
        let url = g.loginURL(state: "state", sessionToken: "tok", scopes: ["user"])
        #expect(url.contains("github.com/login/oauth/authorize"))
        #expect(url.contains("scope=user"))
    }

    @Test func facebookLoginURLContainsExpectedParams() {
        FacebookConfig.appid = "fb_id"
        FacebookConfig.secret = "fb_secret"
        FacebookConfig.endpointAfterAuth = "https://myapp.com/auth/facebook"
        let f = Facebook(clientID: "fb_id", clientSecret: "fb_secret")
        let url = f.loginURL(state: "state", sessionToken: "tok")
        #expect(url.contains("facebook.com/dialog/oauth"))
        #expect(url.contains("client_id=fb_id"))
    }

    @Test func slackLoginURLContainsExpectedParams() {
        SlackConfig.appid = "slack_id"
        SlackConfig.secret = "slack_secret"
        SlackConfig.endpointAfterAuth = "https://myapp.com/auth/slack"
        let s = Slack(clientID: "slack_id", clientSecret: "slack_secret")
        let url = s.loginURL(state: "state", sessionToken: "tok")
        #expect(url.contains("slack.com/oauth/authorize"))
    }

    @Test func salesforceLoginURLContainsExpectedParams() {
        SalesForceConfig.appid = "sf_id"
        SalesForceConfig.secret = "sf_secret"
        SalesForceConfig.endpointAfterAuth = "https://myapp.com/auth/salesforce"
        let s = SalesForce(clientID: "sf_id", clientSecret: "sf_secret")
        let url = s.loginURL(state: "state", sessionToken: "tok")
        #expect(url.contains("salesforce.com/services/oauth2/authorize"))
    }

    @Test func linkedinLoginURLContainsExpectedParams() {
        LinkedinConfig.appid = "li_id"
        LinkedinConfig.secret = "li_secret"
        LinkedinConfig.endpointAfterAuth = "https://myapp.com/auth/linkedin"
        let l = Linkedin(clientID: "li_id", clientSecret: "li_secret")
        let url = l.loginURL(state: "state", sessionToken: "tok")
        #expect(url.contains("linkedin.com/oauth/v2/authorization"))
        #expect(url.contains("scope=openid"))
    }
}
