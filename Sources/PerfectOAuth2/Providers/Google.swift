import Foundation

/// Google sign-in (OpenID Connect over the authorization-code flow).
///
/// - Endpoints: `accounts.google.com/o/oauth2/v2/auth`, `oauth2.googleapis.com/token`, and the OIDC
///   userinfo endpoint `openidconnect.googleapis.com/v1/userinfo`.
/// - Default scopes `openid profile`; `openid` is always added, so every exchange returns an id_token.
/// - PKCE on by default.
/// - Every id_token from the exchange is checked: issuer, audience (this client ID), expiry and
///   subject. With `restrictedDomain`, its `hd` claim must match (see the README's trust model).
public final class Google: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "google"
    /// Only accept accounts in this Google Workspace domain (the id_token's `hd` claim).
    public let restrictedDomain: String?

    static let issuers: Set<String> = ["https://accounts.google.com", "accounts.google.com"]
    static let userInfoURL = URL(string: "https://openidconnect.googleapis.com/v1/userinfo")!

    public init(configuration: OAuth2ClientConfiguration, restrictedDomain: String? = nil) {
        var configuration = configuration
        if let scopes = configuration.scopes, !scopes.contains("openid") {
            configuration.scopes = ["openid"] + scopes
        }
        self.oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!,
            tokenURL: URL(string: "https://oauth2.googleapis.com/token")!,
            defaultScopes: ["openid", "profile"],
            usesPKCEByDefault: true
        )
        self.restrictedDomain = restrictedDomain?.lowercased()
    }

    public var authorizationParameters: [URLQueryItem] {
        restrictedDomain.map { [URLQueryItem(name: "hd", value: $0)] } ?? []
    }

    /// Builds the login link.
    ///
    /// - Parameter offlineAccess: request a refresh token. Adds `access_type=offline` and
    ///   `prompt=consent`: Google only issues a refresh token the first time a user grants offline
    ///   access or when consent is prompted again. Leave it off for routine sign-ins once a refresh
    ///   token is stored, so users aren't asked to consent every time.
    public func authorizationRequest(
        scopes: [String]? = nil,
        state: String? = nil,
        offlineAccess: Bool,
        additionalParameters: [URLQueryItem] = []
    ) throws -> AuthorizationRequest {
        var extra = additionalParameters
        if offlineAccess {
            extra += [URLQueryItem(name: "access_type", value: "offline"), URLQueryItem(name: "prompt", value: "consent")]
        }
        let scopes = scopes.map { $0.contains("openid") ? $0 : ["openid"] + $0 }
        return try authorizationRequest(scopes: scopes, state: state, additionalParameters: extra)
    }

    public func validate(_ token: OAuth2Token) throws {
        _ = try validatedClaims(token)
    }

    func validatedClaims(_ token: OAuth2Token) throws -> IDTokenClaims? {
        guard let idToken = token.idToken else {
            if restrictedDomain != nil { throw OAuth2Error.invalidIDToken("no id_token; request the openid scope") }
            return nil
        }
        let claims = try IDTokenClaims.validate(idToken, issuers: Self.issuers, clientID: oauth2.clientID)
        if let restrictedDomain {
            guard claims.claims["hd"]?.stringValue?.lowercased() == restrictedDomain else {
                throw OAuth2Error.restrictedDomainMismatch
            }
        }
        return claims
    }

    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let claims = try validatedClaims(token)
        let info = try await oauth2.getJSON(Self.userInfoURL, accessToken: token.accessToken)
        if let claims, let sub = info["sub"]?.stringValue, sub != claims.subject {
            throw OAuth2Error.invalidResponse("userinfo subject differs from the id_token subject")
        }
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
