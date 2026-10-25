import Foundation

/// Salesforce (production, sandbox or My Domain login hosts).
///
/// - Endpoints: `<loginHost>/services/oauth2/authorize` and `/services/oauth2/token`; the profile
///   comes from the identity URL (`id`) in the token response.
/// - Default scope `id`. Add `refresh_token` to get a refresh token.
/// - PKCE on by default (Salesforce supports S256, and newer connected apps require it).
/// - The identity URL must be HTTPS on a Salesforce host (`*.salesforce.com`,
///   `*.salesforce.mil`, or the login host) before the access token is sent to it.
public final class Salesforce: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "salesforce"
    public let loginHost: String

    /// - Parameter loginHost: `login.salesforce.com` (default), `test.salesforce.com` for sandboxes,
    ///   or a My Domain host such as `example.my.salesforce.com`.
    public init(configuration: OAuth2ClientConfiguration, loginHost: String = "login.salesforce.com") throws {
        let host = loginHost.lowercased()
        guard !host.isEmpty, host.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }),
              let authorizationURL = URL(string: "https://\(host)/services/oauth2/authorize"),
              let tokenURL = URL(string: "https://\(host)/services/oauth2/token") else {
            throw OAuth2Error.invalidConfiguration("loginHost must be a host name")
        }
        self.loginHost = host
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: authorizationURL,
            tokenURL: tokenURL,
            defaultScopes: ["id"],
            usesPKCEByDefault: true
        )
    }

    func isSalesforceHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased() else { return false }
        if host == loginHost { return true }
        return [".salesforce.com", ".salesforce.mil"].contains { host.hasSuffix($0) }
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        guard let idURLString = token.idURL, let idURL = URL(string: idURLString) else {
            throw OAuth2Error.invalidResponse("token response has no identity URL (id)")
        }
        guard idURL.scheme?.lowercased() == "https", isSalesforceHost(idURL.host) else {
            throw OAuth2Error.insecureURL("identity URL is not an https Salesforce URL")
        }
        let identity = try await oauth2.getJSON(idURL, accessToken: token.accessToken)
        return try OAuthUserProfile(
            userid: identity["user_id"]?.stringValue,
            firstName: identity["first_name"]?.stringValue,
            lastName: identity["last_name"]?.stringValue,
            displayName: identity["display_name"]?.stringValue,
            picture: identity["photos"]?["picture"]?.stringValue,
            email: identity["email"]?.stringValue,
            emailVerified: identity["email_verified"]?.boolValue == true,
            loginType: loginType,
            token: token,
            raw: identity
        )
    }
}
