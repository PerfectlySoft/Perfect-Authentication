import Foundation

/// Sign in with Slack (OpenID Connect).
///
/// - Endpoints: `slack.com/openid/connect/authorize`, `slack.com/api/openid.connect.token`, and
///   `slack.com/api/openid.connect.userInfo`. 1.x used the legacy `oauth/authorize` +
///   `users.identity` flow with `identity.basic` scopes, which only classic Slack apps can use.
/// - Default scopes `openid profile`; add `email` for the address.
/// - PKCE off by default (Slack's PKCE support is recent and not documented for this flow; enable it
///   with `usePKCE: true` if your app supports it).
/// - Slack errors come back as HTTP 200 `{"ok": false, "error": "..."}`; they surface as
///   `OAuth2Error.providerError`.
/// - Slack user ids are scoped to a workspace: key accounts on `userid` together with the team id in
///   `raw["https://slack.com/team_id"]` if users can come from several workspaces.
public final class Slack: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "slack"

    static let userInfoURL = URL(string: "https://slack.com/api/openid.connect.userInfo")!

    public init(configuration: OAuth2ClientConfiguration) {
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://slack.com/openid/connect/authorize")!,
            tokenURL: URL(string: "https://slack.com/api/openid.connect.token")!,
            defaultScopes: ["openid", "profile"],
            usesPKCEByDefault: false
        )
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let info = try await oauth2.getJSON(Self.userInfoURL, accessToken: token.accessToken)
        return try OAuthUserProfile(
            userid: info["sub"]?.stringValue ?? info["https://slack.com/user_id"]?.stringValue,
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
