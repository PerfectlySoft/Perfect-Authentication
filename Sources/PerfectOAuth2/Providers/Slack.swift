import Foundation

public struct SlackConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    public init() {}
}

public class Slack: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://slack.com/oauth/authorize",
            tokenURL: "https://slack.com/api/oauth.access"
        )
    }

    public func getUserData(_ accessToken: String) async -> [String: Any] {
        let url = "https://slack.com/api/users.identity?token=\(accessToken)"
        let data = await makeRequest(.get, url)
        var out = [String: Any]()
        out["userid"] = digIntoDictionary(mineFor: ["user", "id"], data: data) as? String ?? ""
        let fullName = digIntoDictionary(mineFor: ["user", "name"], data: data) as? String ?? ""
        let parts = fullName.components(separatedBy: " ")
        if !parts.isEmpty { out["first_name"] = parts.first }
        if parts.count > 1 { out["last_name"] = parts.last }
        out["picture"] = digIntoDictionary(mineFor: ["user", "image_192"], data: data) as? String ?? ""
        return out
    }

    public func loginURL(state: String, sessionToken: String, scopes: [String] = ["identity.basic", "identity.avatar"]) -> String {
        let redirectURL = "\(SlackConfig.endpointAfterAuth)?session=\(sessionToken)"
        return getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        let redirectURL = "\(SlackConfig.endpointAfterAuth)?session=\(sessionToken)"
        return try await exchange(code: code, state: state, redirectURL: redirectURL)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = ["identity.basic", "identity.avatar"]) -> String {
        Slack(clientID: SlackConfig.appid, clientSecret: SlackConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = Slack(clientID: SlackConfig.appid, clientSecret: SlackConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        let userdata = await provider.getUserData(token.accessToken)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "slack"
        )
    }
}
