import Foundation

private let urlValueAllowed = CharacterSet(
    charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

extension String {
    var urlEncoded: String {
        addingPercentEncoding(withAllowedCharacters: urlValueAllowed) ?? self
    }
}

open class OAuth2: @unchecked Sendable {
    public let clientID: String
    public let clientSecret: String
    public let authorizationURL: String
    public let tokenURL: String

    public init(clientID: String, clientSecret: String, authorizationURL: String, tokenURL: String) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.authorizationURL = authorizationURL
        self.tokenURL = tokenURL
    }

    open func getLoginLink(redirectURL: String, state: String, scopes: [String] = []) -> String {
        var url = "\(authorizationURL)?response_type=code"
        url += "&client_id=\(clientID.urlEncoded)"
        url += "&redirect_uri=\(redirectURL.urlEncoded)"
        url += "&state=\(state.urlEncoded)"
        url += "&scope=\((scopes.joined(separator: " ")).urlEncoded)"
        return url
    }

    open func exchange(authorizationCode: AuthorizationCode) async throws -> OAuth2Token {
        let postBody = [
            "grant_type": "authorization_code",
            "client_id": clientID,
            "client_secret": clientSecret,
            "redirect_uri": authorizationCode.redirectURL,
            "code": authorizationCode.code,
        ]
        let data = await makeRequest(.post, tokenURL, body: urlencode(dict: postBody), encoding: "form")
        guard let token = OAuth2Token(json: data) else {
            if let error = OAuth2Error(json: data) {
                throw error
            }
            throw InvalidAPIResponse()
        }
        return token
    }

    open func exchange(code: String, state: String, redirectURL: String) async throws -> OAuth2Token {
        return try await exchange(authorizationCode: AuthorizationCode(code: code, redirectURL: redirectURL))
    }

    /// Obtains a new access token using a refresh token (RFC 6749 §6).
    ///
    /// Many providers (Google among them) omit `refresh_token` from the refresh response; in that case
    /// the returned token carries the `refreshToken` passed in, so it can be stored as-is.
    ///
    /// - Parameters:
    ///   - refreshToken: the refresh token issued with an earlier access token.
    ///   - scopes: optional subset of the originally granted scopes; omitted from the request when empty.
    ///   - includeClientSecret: send `client_secret` in the body. Confidential clients (Google,
    ///     Salesforce, LinkedIn) need it; pass `false` for public clients that only send `client_id`.
    ///
    /// Provider-specific checks done at exchange time (e.g. Google's `restrictedDomain`) are not
    /// repeated here; the refresh token already came from a checked exchange.
    ///
    /// - Throws: `OAuth2Error` if the provider returns an RFC 6749 error code, otherwise `InvalidAPIResponse`.
    open func refresh(
        refreshToken: String,
        scopes: [String] = [],
        includeClientSecret: Bool = true
    ) async throws -> OAuth2Token {
        var postBody = [
            "grant_type": "refresh_token",
            "client_id": clientID,
            "refresh_token": refreshToken,
        ]
        if !scopes.isEmpty {
            postBody["scope"] = scopes.joined(separator: " ")
        }
        if includeClientSecret {
            postBody["client_secret"] = clientSecret
        }
        var data = await makeRequest(.post, tokenURL, body: urlencode(dict: postBody), encoding: "form")
        if data["access_token"] != nil, data["refresh_token"] == nil {
            data["refresh_token"] = refreshToken
        }
        guard let token = OAuth2Token(json: data) else {
            if let error = OAuth2Error(json: data) {
                throw error
            }
            throw InvalidAPIResponse()
        }
        return token
    }
}
