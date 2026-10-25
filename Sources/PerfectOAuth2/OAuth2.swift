import Foundation

/// Credentials and options for one OAuth2 client registration.
///
/// The description and mirror hide `clientSecret`.
public struct OAuth2ClientConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
    public var clientID: String
    /// Nil for a public client that authenticates with `client_id` and PKCE only.
    public var clientSecret: String?
    /// The registered redirect URI: the route that handles the callback. Sent unchanged in both the
    /// authorization request and the code exchange. Must be absolute HTTPS (or HTTP to a loopback host)
    /// with no fragment.
    public var redirectURL: URL
    /// Scopes to request; nil uses the provider's defaults.
    public var scopes: [String]?
    /// Whether to use PKCE; nil uses the provider's default (see the README's provider table).
    public var usePKCE: Bool?
    public var http: OAuth2HTTPOptions

    public init(
        clientID: String,
        clientSecret: String?,
        redirectURL: URL,
        scopes: [String]? = nil,
        usePKCE: Bool? = nil,
        http: OAuth2HTTPOptions = OAuth2HTTPOptions()
    ) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURL = redirectURL
        self.scopes = scopes
        self.usePKCE = usePKCE
        self.http = http
    }

    public var description: String {
        "OAuth2ClientConfiguration(clientID: \(clientID), clientSecret: \(clientSecret == nil ? "nil" : "<redacted>"), redirectURL: \(redirectURL))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "clientID": clientID,
            "clientSecret": clientSecret == nil ? "nil" : "<redacted>",
            "redirectURL": redirectURL,
            "scopes": scopes as Any,
            "usePKCE": usePKCE as Any,
            "http": http,
        ], displayStyle: .struct)
    }
}

/// HTTP limits for token and profile requests.
public struct OAuth2HTTPOptions: Sendable {
    /// Deadline for each whole request, in seconds.
    public var timeout: TimeInterval
    /// Largest response body accepted. Token and profile responses are a few KB.
    public var maximumResponseBytes: Int
    /// Replaces the default `URLSessionTransport(timeout:maximumResponseBytes:)`.
    public var transport: (any OAuth2Transport)?
    public var userAgent: String

    public init(
        timeout: TimeInterval = 30,
        maximumResponseBytes: Int = 1 << 20,
        transport: (any OAuth2Transport)? = nil,
        userAgent: String = "PerfectOAuth2/2.0"
    ) {
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
        self.transport = transport
        self.userAgent = userAgent
    }
}

/// The authorization-code flow (RFC 6749 §4.1) with PKCE (RFC 7636) for one provider's endpoints.
///
/// Use it directly for any standards-following provider, or wrap it in an `OAuth2Provider` that adds
/// a profile fetch. It is `final` and immutable, so it is checked `Sendable`; customise providers by
/// composition (`OAuth2Provider`), not subclassing.
public final class OAuth2: Sendable {
    public let configuration: OAuth2ClientConfiguration
    public let authorizationURL: URL
    public let tokenURL: URL
    public let defaultScopes: [String]
    /// Whether authorization requests carry `code_challenge` and exchanges `code_verifier`.
    public let usesPKCE: Bool
    let transport: any OAuth2Transport

    public var clientID: String { configuration.clientID }

    /// - Parameters:
    ///   - defaultScopes: used when `configuration.scopes` is nil.
    ///   - usesPKCEByDefault: used when `configuration.usePKCE` is nil.
    public init(
        configuration: OAuth2ClientConfiguration,
        authorizationURL: URL,
        tokenURL: URL,
        defaultScopes: [String] = [],
        usesPKCEByDefault: Bool = true
    ) {
        self.configuration = configuration
        self.authorizationURL = authorizationURL
        self.tokenURL = tokenURL
        self.defaultScopes = defaultScopes
        self.usesPKCE = configuration.usePKCE ?? usesPKCEByDefault
        self.transport = configuration.http.transport ?? URLSessionTransport(
            timeout: configuration.http.timeout,
            maximumResponseBytes: configuration.http.maximumResponseBytes
        )
    }

    static let reservedParameters: Set<String> = [
        "response_type", "client_id", "redirect_uri", "state", "scope",
        "code_challenge", "code_challenge_method",
    ]

    /// Builds the login link and the values to keep for the callback.
    ///
    /// - Parameters:
    ///   - scopes: overrides the configured or default scopes.
    ///   - state: a state you generated; nil generates one with `AuthorizationState.generate()`. It
    ///     must be at least `AuthorizationState.minimumLength` characters.
    ///   - additionalParameters: extra query parameters (e.g. `prompt`). They can't replace the ones
    ///     this method sets.
    public func authorizationRequest(
        scopes: [String]? = nil,
        state: String? = nil,
        additionalParameters: [URLQueryItem] = []
    ) throws -> AuthorizationRequest {
        let redirectURL = configuration.redirectURL
        try Self.validateRedirectURL(redirectURL)
        try requireSecure(authorizationURL, "authorization URL")
        let state = state ?? AuthorizationState.generate()
        try AuthorizationState.validateStored(state)
        for item in additionalParameters where Self.reservedParameters.contains(item.name) {
            throw OAuth2Error.invalidConfiguration("parameter \(item.name) is set by authorizationRequest")
        }

        var items = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURL.absoluteString),
            URLQueryItem(name: "state", value: state),
        ]
        let scopeList = scopes ?? configuration.scopes ?? defaultScopes
        if !scopeList.isEmpty {
            items.append(URLQueryItem(name: "scope", value: scopeList.joined(separator: " ")))
        }
        var verifier: String?
        if usesPKCE {
            let codeVerifier = PKCE.generateVerifier()
            verifier = codeVerifier
            items.append(URLQueryItem(name: "code_challenge", value: PKCE.challenge(for: codeVerifier)))
            items.append(URLQueryItem(name: "code_challenge_method", value: "S256"))
        }
        items += additionalParameters
        let url = try appendingQueryItems(items, to: authorizationURL)
        return AuthorizationRequest(
            url: url,
            pending: PendingAuthorization(state: state, codeVerifier: verifier, redirectURL: redirectURL)
        )
    }

    /// Checks the callback's `state` against `pending.state`, then exchanges the code.
    ///
    /// - Throws: `OAuth2Error.authorizationDenied` if the provider sent an error,
    ///   `.stateMismatch`/`.invalidState` if the state check fails (before any network request),
    ///   `.missingAuthorizationCode`, or the errors of the token request.
    public func exchange(callback: AuthorizationCallback, pending: PendingAuthorization) async throws -> OAuth2Token {
        try AuthorizationState.verify(returned: callback.state, expected: pending.state)
        if let error = callback.error { throw OAuth2Error.authorizationDenied(error) }
        guard let code = callback.code, !code.isEmpty else { throw OAuth2Error.missingAuthorizationCode }
        if usesPKCE, pending.codeVerifier == nil {
            throw OAuth2Error.invalidConfiguration("PKCE is enabled but the pending authorization has no code verifier")
        }

        var fields: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", pending.redirectURL.absoluteString),
            ("client_id", clientID),
        ]
        if let secret = configuration.clientSecret { fields.append(("client_secret", secret)) }
        if let verifier = pending.codeVerifier { fields.append(("code_verifier", verifier)) }
        let json = try await postForm(tokenURL, fields: fields, secrets: [code, pending.codeVerifier])
        return try OAuth2Token(json: json)
    }

    /// Obtains a new access token with a refresh token (RFC 6749 §6).
    ///
    /// Many providers (Google among them) omit `refresh_token` from the response; the returned token
    /// then carries the `refreshToken` passed in, so it can be stored as is.
    ///
    /// - Parameters:
    ///   - scopes: optional subset of the granted scopes; omitted from the request when empty.
    ///   - includeClientSecret: send `client_secret` (when configured). Pass `false` for providers that
    ///     reject it on refresh.
    public func refresh(
        refreshToken: String,
        scopes: [String] = [],
        includeClientSecret: Bool = true
    ) async throws -> OAuth2Token {
        var fields: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", clientID),
        ]
        if !scopes.isEmpty { fields.append(("scope", scopes.joined(separator: " "))) }
        if includeClientSecret, let secret = configuration.clientSecret {
            fields.append(("client_secret", secret))
        }
        let json = try await postForm(tokenURL, fields: fields, secrets: [refreshToken])
        let token = try OAuth2Token(json: json)
        return token.refreshToken == nil ? token.replacingRefreshToken(refreshToken) : token
    }

    /// GETs a JSON object from a provider API with `Authorization: Bearer <accessToken>`.
    ///
    /// - Throws: `.insecureURL` for a non-HTTPS URL, `.providerError` for an error object,
    ///   `.httpStatus` for other non-2xx responses, `.invalidResponse` if the body isn't a JSON object,
    ///   and the transport's errors.
    public func getJSON(
        _ url: URL,
        accessToken: String,
        headers: [String: String] = [:]
    ) async throws -> JSONValue {
        try requireSecure(url, "API URL")
        var allHeaders = baseHeaders
        allHeaders["Authorization"] = "Bearer \(accessToken)"
        allHeaders.merge(headers) { _, new in new }
        let request = OAuth2HTTPRequest(method: .get, url: url, headers: allHeaders)
        return try await sendExpectingObject(request, secrets: [accessToken])
    }

    // MARK: - Internals

    private var baseHeaders: [String: String] {
        [
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": configuration.http.userAgent,
        ]
    }

    private func postForm(_ url: URL, fields: [(String, String)], secrets: [String?]) async throws -> JSONValue {
        try requireSecure(url, "token URL")
        var headers = baseHeaders
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        let request = OAuth2HTTPRequest(method: .post, url: url, headers: headers, body: formEncode(fields))
        return try await sendExpectingObject(request, secrets: secrets)
    }

    private func sendExpectingObject(_ request: OAuth2HTTPRequest, secrets: [String?]) async throws -> JSONValue {
        let response = try await transport.send(request)
        let limit = configuration.http.maximumResponseBytes
        // Also checked here so a custom transport can't hand back an oversized body.
        guard response.body.count <= limit else { throw OAuth2Error.responseTooLarge(limit: limit) }
        let json = try? JSONValue(data: response.body)
        let redact = (secrets + [configuration.clientSecret]).compactMap { $0 }
        if let json, let error = OAuth2ErrorResponse.parse(json, redacting: redact) {
            throw OAuth2Error.providerError(error)
        }
        guard (200..<300).contains(response.status) else { throw OAuth2Error.httpStatus(response.status) }
        guard let json else { throw OAuth2Error.invalidResponse("response is not JSON") }
        guard json.objectValue != nil else { throw OAuth2Error.invalidResponse("response is not a JSON object") }
        return json
    }

    static func validateRedirectURL(_ url: URL) throws {
        try requireSecure(url, "redirect URL")
        guard url.host?.isEmpty == false else { throw OAuth2Error.invalidConfiguration("redirect URL has no host") }
        guard url.fragment == nil else {
            throw OAuth2Error.invalidConfiguration("redirect URL must not have a fragment (RFC 6749 §3.1.2)")
        }
    }
}
