import Foundation

public struct SalesForceConfig {
    nonisolated(unsafe) public static var appid = ""
    nonisolated(unsafe) public static var secret = ""
    nonisolated(unsafe) public static var endpointAfterAuth = ""
    nonisolated(unsafe) public static var redirectAfterAuth = ""
    public init() {}
}

public class SalesForce: OAuth2, @unchecked Sendable {
    public init(clientID: String, clientSecret: String) {
        super.init(
            clientID: clientID,
            clientSecret: clientSecret,
            authorizationURL: "https://login.salesforce.com/services/oauth2/authorize",
            tokenURL: "https://login.salesforce.com/services/oauth2/token"
        )
    }

    // idURL is the user info endpoint returned in the token response
    public func getUserData(_ accessToken: String, _ idURL: String) async -> [String: Any] {
        let data = await makeRequest(.get, idURL, bearerToken: accessToken)
        var out = [String: Any]()
        if let n = data["user_id"] as? String { out["userid"] = n }
        if let n = data["first_name"] as? String { out["first_name"] = n }
        if let n = data["last_name"] as? String { out["last_name"] = n }
        out["picture"] = digIntoDictionary(mineFor: ["photos", "picture"], data: data) as? String ?? ""
        return out
    }

    public func loginURL(state: String, sessionToken: String, scopes: [String] = ["id"]) -> String {
        let redirectURL = "\(SalesForceConfig.endpointAfterAuth)?session=\(sessionToken)"
        return getLoginLink(redirectURL: redirectURL, state: state, scopes: scopes)
    }

    public func exchange(code: String, state: String, sessionToken: String) async throws -> OAuth2Token {
        let redirectURL = "\(SalesForceConfig.endpointAfterAuth)?session=\(sessionToken)"
        return try await exchange(code: code, state: state, redirectURL: redirectURL)
    }

    public static func loginURL(state: String, sessionToken: String, scopes: [String] = ["id"]) -> String {
        SalesForce(clientID: SalesForceConfig.appid, clientSecret: SalesForceConfig.secret)
            .loginURL(state: state, sessionToken: sessionToken, scopes: scopes)
    }

    public static func processAuthResponse(
        code: String,
        state: String,
        sessionCSRF: String,
        sessionToken: String
    ) async throws -> OAuthUserProfile {
        guard state == sessionCSRF else { throw OAuth2Error(code: .unsupportedResponseType) }
        let provider = SalesForce(clientID: SalesForceConfig.appid, clientSecret: SalesForceConfig.secret)
        let token = try await provider.exchange(code: code, state: state, sessionToken: sessionToken)
        guard let idURL = token.idURL else { throw InvalidAPIResponse() }
        let userdata = await provider.getUserData(token.accessToken, idURL)
        return OAuthUserProfile(
            userid: userdata["userid"] as? String ?? "",
            firstName: userdata["first_name"] as? String,
            lastName: userdata["last_name"] as? String,
            picture: userdata["picture"] as? String,
            accessToken: token.accessToken,
            refreshToken: token.refreshToken,
            loginType: "salesforce"
        )
    }
}
