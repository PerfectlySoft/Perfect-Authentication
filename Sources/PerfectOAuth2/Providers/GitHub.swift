import Foundation

/// GitHub OAuth apps (and GitHub Apps' user authorization).
///
/// - Endpoints: `github.com/login/oauth/authorize`, `github.com/login/oauth/access_token`, and the
///   REST API's `api.github.com/user`.
/// - Default scope `read:user` (1.x requested `user`, which also grants profile *write* access).
/// - PKCE on by default (GitHub added S256 support in 2025).
/// - GitHub reports token errors with HTTP 200 and an `error` field; they surface as
///   `OAuth2Error.providerError` (e.g. `bad_verification_code`).
/// - `email` is the public profile email and is never marked verified; use the `user:email` scope and
///   `GET /user/emails` if you need a verified address.
public final class GitHub: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "github"

    static let userURL = URL(string: "https://api.github.com/user")!

    public init(configuration: OAuth2ClientConfiguration) {
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://github.com/login/oauth/authorize")!,
            tokenURL: URL(string: "https://github.com/login/oauth/access_token")!,
            defaultScopes: ["read:user"],
            usesPKCEByDefault: true
        )
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let user = try await oauth2.getJSON(Self.userURL, accessToken: token.accessToken, headers: [
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        ])
        let name = user["name"]?.stringValue
        let (first, last) = splitName(name)
        return try OAuthUserProfile(
            userid: user["id"]?.identifierValue,
            firstName: first,
            lastName: last,
            displayName: name ?? user["login"]?.stringValue,
            picture: user["avatar_url"]?.stringValue,
            email: user["email"]?.stringValue,
            emailVerified: false,
            loginType: loginType,
            token: token,
            raw: user
        )
    }
}

/// Splits "First Middle Last" into ("First", "Last"); a single word is a first name.
func splitName(_ name: String?) -> (String?, String?) {
    guard let name else { return (nil, nil) }
    let parts = name.split(separator: " ").map(String.init)
    guard let first = parts.first else { return (nil, nil) }
    return (first, parts.count > 1 ? parts.last : nil)
}
