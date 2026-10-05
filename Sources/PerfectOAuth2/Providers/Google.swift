import Foundation

public struct GoogleConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    nonisolated(unsafe) public static var restrictedDomain: String? = nil
    public init() {}
}

public class Google: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://accounts.google.com/o/oauth2/auth",
            tokenURL: "https://www.googleapis.com/oauth2/v4/token"
        )
    }

    public func getUserData(_ accessToken: String) async -> [String: Any] {
        let fields = ["family_name", "given_name", "id", "picture"].joined(separator: "%2C")
        let url = "https://www.googleapis.com/oauth2/v2/userinfo?fields=\(fields)&access_token=\(accessToken)"
        let data = await makeRequest(.get, url)
        var out = [String: Any]()
        if let n = data["id"] as? String { out["userid"] = n }
        if let n = data["given_name"] as? String { out["first_name"] = n }
        if let n = data["family_name"] as? String { out["last_name"] = n }
        if let n = data["picture"] as? String { out["picture"] = n }
        return out
    }

    /// Builds the Google sign-in link without requesting offline access.
    public func loginURL(state: String, sessionToken: String, scopes: [String] = ["profile"]) -> String {
        loginURL(state: state, sessionToken: sessionToken, scopes: scopes, offlineAccess: false)
    }

    /// Builds the Google sign-in link.
    ///
    /// - Parameter offlineAccess: request a refresh token. Adds `access_type=offline` and
    ///   `prompt=consent`: Google only issues a refresh token the first time a user grants offline
    ///   access or when consent is prompted again, so without `prompt=consent` a returning user would
    ///   get none. Pass `false` for ordinary sign-ins once a refresh token is stored, so users aren't
    ///   asked to consent every time.
    public func loginURL(
        state: String,
        sessionToken: String,
        scopes: [String] = ["profile"],
        offlineAccess: Bool
    ) -> String {
        let redirectURL = "\(GoogleConfig.endpointAfterAuth)?session=\(sessionToken)"
        var url = getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
        if let domain = GoogleConfig.restrictedDomain {
            url += "&hd=\(domain)"
        }
        if offlineAccess {
            url += "&access_type=offline&prompt=consent"
        }
        return url
    }

    public override func exchange(code: String, state: String, redirectURL: String) async throws -> OAuth2Token {
        let token = try await super.exchange(code: code, state: state, redirectURL: redirectURL)
        if let domain = GoogleConfig.restrictedDomain {
            guard let hd = token.webToken?["hd"] as? String, hd == domain else {
                throw OAuth2Error(code: .unsupportedResponseType)
            }
        }
        return token
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        let redirectURL = "\(GoogleConfig.endpointAfterAuth)?session=\(sessionToken)"
        return try await exchange(code: code, state: state, redirectURL: redirectURL)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = ["profile"]) -> String {
        loginURL(state: state, sessionToken: sessionToken, scopes: scopes, offlineAccess: false)
    }

    public static func loginURL(
        state: String,
        sessionToken: String,
        scopes: [String] = ["profile"],
        offlineAccess: Bool
    ) -> String {
        Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes, offlineAccess: offlineAccess)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        let userdata = await provider.getUserData(token.accessToken)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "google"
        )
    }
}
