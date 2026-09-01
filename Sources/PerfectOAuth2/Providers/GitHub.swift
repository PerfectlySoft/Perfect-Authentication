import Foundation

public struct GitHubConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    public init() {}
}

public class GitHub: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://github.com/login/oauth/authorize",
            tokenURL: "https://github.com/login/oauth/access_token"
        )
    }

    public func getUserData(_ accessToken: String) async -> [String: Any] {
        let data = await makeRequest(.get, "https://api.github.com/user", bearerToken: accessToken)
        var out = [String: Any]()
        if let n = data["id"] { out["userid"] = "\(n)" }
        if let n = data["name"] as? String {
            let parts = n.components(separatedBy: " ")
            if !parts.isEmpty { out["first_name"] = parts.first }
            if parts.count > 1 { out["last_name"] = parts.last }
        }
        if let n = data["avatar_url"] as? String { out["picture"] = n }
        return out
    }

    public func loginURL(state: String, sessionToken: String, scopes: [String] = []) -> String {
        let redirectURL = "\(GitHubConfig.endpointAfterAuth)?session=\(sessionToken)"
        return getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        let redirectURL = "\(GitHubConfig.endpointAfterAuth)?session=\(sessionToken)"
        return try await exchange(code: code, state: state, redirectURL: redirectURL)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = ["user"]) -> String {
        GitHub(clientID: GitHubConfig.appid, clientSecret: GitHubConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = GitHub(clientID: GitHubConfig.appid, clientSecret: GitHubConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        let userdata = await provider.getUserData(token.accessToken)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "github"
        )
    }
}
