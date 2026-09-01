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

    public func loginURL(state: String, sessionToken: String, scopes: [String] = ["profile"]) -> String {
        let redirectURL = "\(GoogleConfig.endpointAfterAuth)?session=\(sessionToken)"
        var url = getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
        if let domain = GoogleConfig.restrictedDomain {
            url += "&hd=\(domain)"
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
        Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
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
