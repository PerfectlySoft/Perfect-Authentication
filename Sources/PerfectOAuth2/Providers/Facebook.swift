import Foundation

public struct FacebookConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    public init() {}
}

public class Facebook: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://www.facebook.com/dialog/oauth",
            tokenURL: "https://graph.facebook.com/v2.3/oauth/access_token"
        )
    }

    public func getUserData(_ accessToken: String) async -> [String: Any] {
        let fields = ["id", "first_name", "last_name", "picture"].joined(separator: "%2C")
        let url = "https://graph.facebook.com/v2.8/me?fields=\(fields)&access_token=\(accessToken)"
        let data = await makeRequest(.get, url)
        var out = [String: Any]()
        if let n = data["id"] as? String { out["userid"] = n }
        if let n = data["first_name"] as? String { out["first_name"] = n }
        if let n = data["last_name"] as? String { out["last_name"] = n }
        out["picture"] = digIntoDictionary(mineFor: ["picture", "data", "url"], data: data) as? String ?? ""
        return out
    }

    public func loginURL(state: String, sessionToken: String, scopes: [String] = []) -> String {
        let redirectURL = "\(FacebookConfig.endpointAfterAuth)?session=\(sessionToken)"
        return getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        let redirectURL = "\(FacebookConfig.endpointAfterAuth)?session=\(sessionToken)"
        return try await exchange(code: code, state: state, redirectURL: redirectURL)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = []) -> String {
        Facebook(clientID: FacebookConfig.appid, clientSecret: FacebookConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = Facebook(clientID: FacebookConfig.appid, clientSecret: FacebookConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        let userdata = await provider.getUserData(token.accessToken)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "facebook"
        )
    }
}
