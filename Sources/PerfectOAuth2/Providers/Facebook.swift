import Crypto
import Foundation

/// Facebook Login (manual flow) and the Graph API `/me` endpoint.
///
/// - The Graph API version is configurable (default `v23.0`; a value that isn't ASCII letters, digits
///   and dots falls back to it). Meta retires versions about two years after release, so bump it.
/// - Default scopes: none (`public_profile` is implied).
/// - PKCE off by default: Meta documents PKCE for some Facebook Login flows, but not clearly for the
///   web code flow with a client secret. Enable it with `usePKCE: true` if your app is set up for it.
/// - The access token is sent in the `Authorization: Bearer` header, not the query string, along with
///   `appsecret_proof` (HMAC-SHA256 of the token keyed with the app secret) when a secret is configured,
///   which apps with "Require App Secret" need.
public final class Facebook: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "facebook"
    public let graphAPIVersion: String

    public init(configuration: OAuth2ClientConfiguration, graphAPIVersion: String = "v23.0") {
        let version = !graphAPIVersion.isEmpty && graphAPIVersion.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == ".") }) ? graphAPIVersion : "v23.0"
        self.graphAPIVersion = version
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://www.facebook.com/\(version)/dialog/oauth")!,
            tokenURL: URL(string: "https://graph.facebook.com/\(version)/oauth/access_token")!,
            defaultScopes: [],
            usesPKCEByDefault: false
        )
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        var items = [URLQueryItem(name: "fields", value: "id,name,first_name,last_name,picture")]
        if let secret = oauth2.configuration.clientSecret {
            items.append(URLQueryItem(name: "appsecret_proof", value: Self.appSecretProof(accessToken: token.accessToken, appSecret: secret)))
        }
        let url = try appendingQueryItems(items, to: URL(string: "https://graph.facebook.com/\(graphAPIVersion)/me")!)
        let me = try await oauth2.getJSON(url, accessToken: token.accessToken)
        return try OAuthUserProfile(
            userid: me["id"]?.identifierValue,
            firstName: me["first_name"]?.stringValue,
            lastName: me["last_name"]?.stringValue,
            displayName: me["name"]?.stringValue,
            picture: me["picture"]?["data"]?["url"]?.stringValue,
            loginType: loginType,
            token: token,
            raw: me
        )
    }

    /// Lowercase hex HMAC-SHA256 of the access token, keyed with the app secret.
    static func appSecretProof(accessToken: String, appSecret: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(accessToken.utf8), using: SymmetricKey(data: Data(appSecret.utf8)))
        return mac.map { String(format: "%02x", $0) }.joined()
    }
}
