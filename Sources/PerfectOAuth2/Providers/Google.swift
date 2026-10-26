import Foundation

/// Google sign-in (OpenID Connect over the authorization-code flow).
///
/// - Endpoints: `accounts.google.com/o/oauth2/v2/auth`, `oauth2.googleapis.com/token`, and the OIDC
///   userinfo endpoint `openidconnect.googleapis.com/v1/userinfo`.
/// - Default scopes `openid profile`. `openid` is always added, however the login link is built, so
///   every exchange returns an id_token.
/// - PKCE on by default. With PKCE off, a `nonce` is sent and checked against the id_token instead.
/// - On every code exchange the id_token is checked: issuer, audience (this client ID), expiry, issue
///   time, subject, the nonce if one was sent, and with `restrictedDomain` its `hd` claim.
/// - `fetchProfile(token:)` accepts any access token and trusts only the userinfo response, which
///   Google returns for that token: with `restrictedDomain`, userinfo's `hd` must match. It never
///   uses the token's id_token, which may not have come from this library's exchange.
public final class Google: OAuth2Provider {
    public let oauth2: OAuth2
    public let loginType = "google"
    /// Only accept accounts in this Google Workspace domain (the `hd` claim and userinfo field).
    public let restrictedDomain: String?

    static let issuers: Set<String> = ["https://accounts.google.com", "accounts.google.com"]
    static let userInfoURL = URL(string: "https://openidconnect.googleapis.com/v1/userinfo")!

    public init(configuration: OAuth2ClientConfiguration, restrictedDomain: String? = nil) {
        var configuration = configuration
        if let scopes = configuration.scopes {
            configuration.scopes = Self.withOpenID(scopes)
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

    static func withOpenID(_ scopes: [String]) -> [String] {
        scopes.contains("openid") ? scopes : ["openid"] + scopes
    }

    public var authorizationParameters: [URLQueryItem] {
        restrictedDomain.map { [URLQueryItem(name: "hd", value: $0)] } ?? []
    }

    public func makeAuthorizationRequest(
        scopes: [String]?,
        state: String?,
        additionalParameters: [URLQueryItem]
    ) throws -> AuthorizationRequest {
        try defaultAuthorizationRequest(
            scopes: scopes.map(Self.withOpenID),
            state: state,
            additionalParameters: additionalParameters,
            nonce: oauth2.usesPKCE ? nil : AuthorizationState.generate()
        )
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
        offlineAccess: Bool = false,
        additionalParameters: [URLQueryItem] = []
    ) throws -> AuthorizationRequest {
        var extra = additionalParameters
        if offlineAccess {
            extra += [URLQueryItem(name: "access_type", value: "offline"), URLQueryItem(name: "prompt", value: "consent")]
        }
        return try makeAuthorizationRequest(scopes: scopes, state: state, additionalParameters: extra)
    }

    /// Validates the id_token from a code exchange (see the type's documentation).
    public func validate(_ token: OAuth2Token, pending: PendingAuthorization) throws {
        guard let idToken = token.idToken else {
            throw OAuth2Error.invalidIDToken("no id_token; request the openid scope")
        }
        let claims = try IDTokenClaims.validate(
            idToken, issuers: Self.issuers, clientID: oauth2.clientID, nonce: pending.nonce
        )
        if let restrictedDomain {
            guard claims.claims["hd"]?.stringValue?.lowercased() == restrictedDomain else {
                throw OAuth2Error.restrictedDomainMismatch
            }
        }
    }

    /// Fetches the userinfo for `token.accessToken` (any access token; see the type's documentation).
    public func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let info = try await oauth2.getJSON(Self.userInfoURL, accessToken: token.accessToken)
        if let restrictedDomain {
            guard info["hd"]?.stringValue?.lowercased() == restrictedDomain else {
                throw OAuth2Error.restrictedDomainMismatch
            }
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
