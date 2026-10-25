import Foundation

/// Sign In with LinkedIn using OpenID Connect.
///
/// - Endpoints: `www.linkedin.com/oauth/v2/authorization`, `www.linkedin.com/oauth/v2/accessToken`,
///   and the OIDC userinfo endpoint `api.linkedin.com/v2/userinfo` (the `r_liteprofile` APIs are gone).
/// - Default scopes `openid profile`; add `email` for `email`/`email_verified`.
/// - PKCE off by default: LinkedIn documents PKCE only for its native-client flow, which needs
///   LinkedIn's approval, so web apps should leave it off.
public final class LinkedIn: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "linkedin"

    static let userInfoURL = URL(string: "https://api.linkedin.com/v2/userinfo")!

    public init(configuration: OAuth2ClientConfiguration) {
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://www.linkedin.com/oauth/v2/authorization")!,
            tokenURL: URL(string: "https://www.linkedin.com/oauth/v2/accessToken")!,
            defaultScopes: ["openid", "profile"],
            usesPKCEByDefault: false
        )
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let info = try await oauth2.getJSON(Self.userInfoURL, accessToken: token.accessToken)
        return try OAuthUserProfile(
            userid: info["sub"]?.stringValue,
            firstName: info["given_name"]?.stringValue,
            lastName: info["family_name"]?.stringValue,
            displayName: info["name"]?.stringValue,
            picture: info["picture"]?.stringValue,
            email: info["email"]?.stringValue,
            emailVerified: info["email_verified"]?.boolValue == true,
            loginType: loginType,
            token: token,
            raw: info
        )
    }
}
