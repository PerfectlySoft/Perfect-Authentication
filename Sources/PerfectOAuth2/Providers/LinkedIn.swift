import Foundation

public struct LinkedinConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    public init() {}
}

public class Linkedin: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://www.linkedin.com/oauth/v2/authorization",
            tokenURL: "https://www.linkedin.com/oauth/v2/accessToken"
        )
    }

    // Uses LinkedIn OpenID Connect userinfo endpoint (v2, requires openid + profile scopes)
    public func getUserData(_ accessToken: String) async -> [String: Any] {
        let data = await makeRequest(.get, "https://api.linkedin.com/v2/userinfo", bearerToken: accessToken)
        var out = [String: Any]()
        if let n = data["sub"] as? String { out["userid"] = n }
        if let n = data["given_name"] as? String { out["first_name"] = n }
        if let n = data["family_name"] as? String { out["last_name"] = n }
        if let n = data["picture"] as? String { out["picture"] = n }
        return out
    }

    public func loginURL(state: String, sessionToken: String, scopes: [String] = ["openid", "profile"]) -> String {
        let redirectURL = LinkedinConfig.endpointAfterAuth
        return getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        return try await exchange(code: code, state: state, redirectURL: LinkedinConfig.endpointAfterAuth)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = ["openid", "profile"]) -> String {
        Linkedin(clientID: LinkedinConfig.appid, clientSecret: LinkedinConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = Linkedin(clientID: LinkedinConfig.appid, clientSecret: LinkedinConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        let userdata = await provider.getUserData(token.accessToken)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "linkedin"
        )
    }
}
