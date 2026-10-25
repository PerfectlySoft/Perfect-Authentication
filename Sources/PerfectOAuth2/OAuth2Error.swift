import Foundation

/// Every error PerfectOAuth2 throws.
///
/// Descriptions never contain client secrets, codes, verifiers or tokens. Text taken from a provider
/// (`OAuth2ErrorResponse.errorDescription`) is truncated, stripped of control characters, and has any
/// secret sent in the failed request replaced with `<redacted>`.
public enum OAuth2Error: Error, Sendable, Equatable, CustomStringConvertible {
    /// The `state` returned to the callback is missing or doesn't match the one stored for the session.
    case stateMismatch
    /// The stored state is unusable: empty, shorter than `AuthorizationState.minimumLength`, or too long.
    case invalidState(String)
    /// The provider redirected back with `error=...` instead of a code (e.g. the user declined).
    case authorizationDenied(OAuth2ErrorResponse)
    /// The callback carried neither `code` nor `error`.
    case missingAuthorizationCode
    /// An error object returned by a token or API endpoint (RFC 6749 §5.2, or a provider's own shape).
    case providerError(OAuth2ErrorResponse)
    /// A non-2xx HTTP status without a recognisable error body. Redirects are not followed, so 3xx
    /// ends up here too.
    case httpStatus(Int)
    /// The response wasn't the JSON expected (not JSON, wrong shape, or a required field is missing).
    case invalidResponse(String)
    /// The response body was larger than `OAuth2HTTPOptions.maximumResponseBytes`.
    case responseTooLarge(limit: Int)
    /// The request didn't complete within `OAuth2HTTPOptions.timeout`.
    case timedOut
    /// A network-level failure (DNS, TLS, connection reset...).
    case network(String)
    /// The provider's profile had no user identifier. Never treat a sign-in without one as a login.
    case missingUserID
    /// An id_token failed validation (issuer, audience, expiry, subject or encoding).
    case invalidIDToken(String)
    /// Google: the account's hosted domain (`hd`) doesn't match `restrictedDomain`.
    case restrictedDomainMismatch
    /// A URL that would carry credentials isn't HTTPS (plain HTTP is only allowed to loopback hosts).
    case insecureURL(String)
    /// The configuration can't be used (e.g. a redirect URL with a fragment).
    case invalidConfiguration(String)

    public var description: String {
        switch self {
        case .stateMismatch: return "OAuth2: state does not match the session (possible CSRF)"
        case .invalidState(let why): return "OAuth2: unusable state: \(why)"
        case .authorizationDenied(let response): return "OAuth2: authorization denied: \(response)"
        case .missingAuthorizationCode: return "OAuth2: callback has no authorization code"
        case .providerError(let response): return "OAuth2: provider error: \(response)"
        case .httpStatus(let status): return "OAuth2: unexpected HTTP status \(status)"
        case .invalidResponse(let why): return "OAuth2: invalid response: \(why)"
        case .responseTooLarge(let limit): return "OAuth2: response larger than \(limit) bytes"
        case .timedOut: return "OAuth2: request timed out"
        case .network(let why): return "OAuth2: network error: \(why)"
        case .missingUserID: return "OAuth2: provider returned no user id"
        case .invalidIDToken(let why): return "OAuth2: invalid id_token: \(why)"
        case .restrictedDomainMismatch: return "OAuth2: account is not in the restricted domain"
        case .insecureURL(let why): return "OAuth2: insecure URL: \(why)"
        case .invalidConfiguration(let why): return "OAuth2: invalid configuration: \(why)"
        }
    }
}

/// An error reported by a provider.
public struct OAuth2ErrorResponse: Sendable, Equatable, CustomStringConvertible {
    /// The provider's error code, e.g. `invalid_grant`, `bad_verification_code`, `OAuthException`.
    public let code: String
    /// The provider's human-readable text, sanitised (see `OAuth2Error`).
    public let errorDescription: String?
    public let errorURI: String?

    /// The RFC 6749 code, when `code` is one of them.
    public var standardCode: OAuth2ErrorCode? { OAuth2ErrorCode(rawValue: code) }

    public init(code: String, errorDescription: String? = nil, errorURI: String? = nil) {
        self.init(code: code, errorDescription: errorDescription, errorURI: errorURI, redacting: [])
    }

    init(code: String, errorDescription: String?, errorURI: String?, redacting secrets: [String]) {
        self.code = Self.sanitize(code, limit: 64, redacting: secrets) ?? "unknown"
        self.errorDescription = Self.sanitize(errorDescription, limit: 256, redacting: secrets)
        self.errorURI = Self.sanitize(errorURI, limit: 256, redacting: secrets)
    }

    public var description: String {
        var text = code
        if let errorDescription { text += " (\(errorDescription))" }
        return text
    }

    static func sanitize(_ text: String?, limit: Int, redacting secrets: [String]) -> String? {
        guard var text, !text.isEmpty else { return nil }
        for secret in secrets where secret.count >= 8 {  // shorter values would mangle ordinary words
            text = text.replacingOccurrences(of: secret, with: "<redacted>")
        }
        let scalars = text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        var cleaned = String(String.UnicodeScalarView(scalars))
        if cleaned.count > limit { cleaned = String(cleaned.prefix(limit)) + "…" }
        return cleaned
    }

    /// Recognises the error shapes providers use:
    /// - RFC 6749: `{"error": "invalid_grant", "error_description": "...", "error_uri": "..."}`
    ///   (GitHub sends this with HTTP 200);
    /// - Slack: `{"ok": false, "error": "invalid_code"}`;
    /// - Facebook Graph: `{"error": {"message": "...", "type": "OAuthException", "code": 190}}`.
    static func parse(_ json: JSONValue, redacting secrets: [String]) -> OAuth2ErrorResponse? {
        guard let error = json["error"] else {
            if json["ok"]?.boolValue == false {
                return OAuth2ErrorResponse(code: "unknown", errorDescription: nil, errorURI: nil, redacting: secrets)
            }
            return nil
        }
        if let code = error.stringValue {
            return OAuth2ErrorResponse(
                code: code,
                errorDescription: json["error_description"]?.stringValue,
                errorURI: json["error_uri"]?.stringValue,
                redacting: secrets
            )
        }
        if error.objectValue != nil {
            let code = error["type"]?.stringValue ?? error["code"]?.identifierValue ?? "unknown"
            return OAuth2ErrorResponse(
                code: code,
                errorDescription: error["message"]?.stringValue,
                errorURI: nil,
                redacting: secrets
            )
        }
        return nil
    }
}

/// The error codes defined by RFC 6749 §4.1.2.1 and §5.2.
public enum OAuth2ErrorCode: String, Sendable {
    case invalidRequest = "invalid_request"
    case invalidClient = "invalid_client"
    case invalidGrant = "invalid_grant"
    case unauthorizedClient = "unauthorized_client"
    case unsupportedGrantType = "unsupported_grant_type"
    case invalidScope = "invalid_scope"
    case accessDenied = "access_denied"
    case unsupportedResponseType = "unsupported_response_type"
    case serverError = "server_error"
    case temporarilyUnavailable = "temporarily_unavailable"
}
