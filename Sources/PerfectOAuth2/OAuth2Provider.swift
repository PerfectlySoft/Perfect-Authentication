import Foundation

/// A provider: an `OAuth2` client plus how to read the signed-in user's profile.
///
/// Conform your own types to add providers this package doesn't ship. Implement `oauth2`,
/// `loginType` and `fetchProfile(token:)`; override `authorizationParameters` and `validate(_:)` if
/// you need extra login-link parameters or token checks.
public protocol OAuth2Provider: Sendable {
    var oauth2: OAuth2 { get }
    /// Identifies the provider in `OAuthUserProfile.loginType`.
    var loginType: String { get }
    /// Extra query parameters for every login link (e.g. Google's `hd`). Their names can't also be
    /// passed in `additionalParameters`.
    var authorizationParameters: [URLQueryItem] { get }
    /// Builds the login link. This is the customisation point behind every `authorizationRequest`
    /// overload, so it is dispatched dynamically, also through `any OAuth2Provider`. The default
    /// implementation adds `authorizationParameters` and calls `OAuth2.authorizationRequest`.
    func makeAuthorizationRequest(
        scopes: [String]?,
        state: String?,
        additionalParameters: [URLQueryItem]
    ) throws -> AuthorizationRequest
    /// Checks run on every token from a code exchange, before it is returned (e.g. Google's id_token
    /// and domain checks). `pending` is the authorization the code was exchanged for.
    func validate(_ token: OAuth2Token, pending: PendingAuthorization) throws
    /// Fetches the user's profile for an access token. Must throw (not return an empty id) when there
    /// is no user id; `OAuthUserProfile.init` does that for you.
    func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile
}

extension OAuth2Provider {
    public var authorizationParameters: [URLQueryItem] { [] }
    public func validate(_ token: OAuth2Token, pending: PendingAuthorization) throws {}

    public func makeAuthorizationRequest(
        scopes: [String]?,
        state: String?,
        additionalParameters: [URLQueryItem]
    ) throws -> AuthorizationRequest {
        try defaultAuthorizationRequest(scopes: scopes, state: state, additionalParameters: additionalParameters)
    }

    /// The default login-link construction, for conformers that customise `makeAuthorizationRequest`
    /// and then delegate.
    public func defaultAuthorizationRequest(
        scopes: [String]?,
        state: String?,
        additionalParameters: [URLQueryItem],
        nonce: String? = nil
    ) throws -> AuthorizationRequest {
        let own = Set(authorizationParameters.map(\.name))
        for item in additionalParameters where own.contains(item.name) {
            throw OAuth2Error.invalidConfiguration("parameter \(item.name) is set by the provider")
        }
        return try oauth2.authorizationRequest(
            scopes: scopes,
            state: state,
            additionalParameters: authorizationParameters + additionalParameters,
            nonce: nonce
        )
    }

    /// Builds the login link; store `pending` in the server-side session.
    public func authorizationRequest(
        scopes: [String]? = nil,
        state: String? = nil,
        additionalParameters: [URLQueryItem] = []
    ) throws -> AuthorizationRequest {
        try makeAuthorizationRequest(scopes: scopes, state: state, additionalParameters: additionalParameters)
    }

    /// Checks state and the pending authorization, exchanges the code, and runs `validate(_:pending:)`.
    public func exchange(callback: AuthorizationCallback, pending: PendingAuthorization) async throws -> OAuth2Token {
        let token = try await oauth2.exchange(callback: callback, pending: pending)
        try validate(token, pending: pending)
        return token
    }
    /// Checks state, exchanges the code, and fetches the profile.
    public func completeAuthorization(
        callback: AuthorizationCallback,
        pending: PendingAuthorization
    ) async throws -> OAuthUserProfile {
        let token = try await exchange(callback: callback, pending: pending)
        return try await fetchProfile(token: token)
    }

    /// `completeAuthorization` with the callback request's URL (its `code`, `state` and `error`).
    public func completeAuthorization(callbackURL: URL, pending: PendingAuthorization) async throws -> OAuthUserProfile {
        try await completeAuthorization(callback: AuthorizationCallback(url: callbackURL), pending: pending)
    }

    /// `completeAuthorization` with the callback's `code` and `state` parameters.
    public func completeAuthorization(
        code: String?,
        state: String?,
        pending: PendingAuthorization
    ) async throws -> OAuthUserProfile {
        try await completeAuthorization(callback: AuthorizationCallback(code: code, state: state), pending: pending)
    }

    /// See `OAuth2.refresh(refreshToken:scopes:includeClientSecret:)`.
    public func refresh(
        refreshToken: String,
        scopes: [String] = [],
        includeClientSecret: Bool = true
    ) async throws -> OAuth2Token {
        try await oauth2.refresh(refreshToken: refreshToken, scopes: scopes, includeClientSecret: includeClientSecret)
    }
}
