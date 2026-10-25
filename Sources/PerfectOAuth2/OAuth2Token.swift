import Foundation

/// A token endpoint response (RFC 6749 §5.1).
///
/// `description`, `debugDescription`, `dump` and `Mirror` hide the access, refresh and id tokens.
public struct OAuth2Token: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let accessToken: String
    /// `token_type`, `Bearer` when the provider omits it.
    public let tokenType: String
    public var refreshToken: String? { refreshTokenStorage }
    private var refreshTokenStorage: String?
    /// `expires_in` in seconds, accepted as a JSON number or a numeric string.
    public let expiresIn: Int?
    /// When the access token expires: the time the response was parsed plus `expiresIn`.
    public let expiration: Date?
    /// Granted scopes. RFC 6749 says space-delimited; GitHub and Slack use commas. Both are split.
    public let scope: [String]?
    /// The raw OpenID Connect id_token, if any. It is *not* validated here; see the README's trust
    /// model before relying on any claim in it.
    public let idToken: String?
    /// Salesforce: `instance_url`.
    public let instanceURL: String?
    /// Salesforce: `id`, the identity URL.
    public let idURL: String?

    public init(
        accessToken: String,
        tokenType: String = "Bearer",
        refreshToken: String? = nil,
        expiresIn: Int? = nil,
        scope: [String]? = nil,
        idToken: String? = nil,
        instanceURL: String? = nil,
        idURL: String? = nil,
        now: Date = Date()
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshTokenStorage = refreshToken
        self.expiresIn = expiresIn
        self.expiration = expiresIn.map { now.addingTimeInterval(TimeInterval($0)) }
        self.scope = scope
        self.idToken = idToken
        self.instanceURL = instanceURL
        self.idURL = idURL
    }

    /// Parses a token response. Throws `OAuth2Error.invalidResponse` without a non-empty `access_token`.
    init(json: JSONValue, now: Date = Date()) throws {
        guard let accessToken = json["access_token"]?.stringValue, !accessToken.isEmpty else {
            throw OAuth2Error.invalidResponse("token response has no access_token")
        }
        var expiresIn: Int?
        if let value = json["expires_in"]?.int64Value, value >= 0, value <= Int64(Int32.max) {
            expiresIn = Int(value)
        }
        let scope = json["scope"]?.stringValue.map {
            $0.split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init)
        }
        let tokenType = json["token_type"]?.stringValue
        self.init(
            accessToken: accessToken,
            tokenType: (tokenType?.isEmpty == false ? tokenType : nil) ?? "Bearer",
            refreshToken: json["refresh_token"]?.stringValue.flatMap { $0.isEmpty ? nil : $0 },
            expiresIn: expiresIn,
            scope: scope,
            idToken: json["id_token"]?.stringValue,
            instanceURL: json["instance_url"]?.stringValue,
            idURL: json["id"]?.stringValue,
            now: now
        )
    }

    /// The same token with `refreshToken` replaced (the refresh grant keeps the old refresh token
    /// when the provider doesn't rotate it).
    func replacingRefreshToken(_ refreshToken: String?) -> OAuth2Token {
        var copy = self
        copy.refreshTokenStorage = refreshToken
        return copy
    }

    public var description: String {
        var parts = ["accessToken: <redacted>", "tokenType: \(tokenType)"]
        parts.append("refreshToken: \(refreshToken == nil ? "nil" : "<redacted>")")
        if let expiration { parts.append("expiration: \(expiration)") }
        if let scope { parts.append("scope: \(scope)") }
        if idToken != nil { parts.append("idToken: <redacted>") }
        return "OAuth2Token(\(parts.joined(separator: ", ")))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "accessToken": "<redacted>",
            "tokenType": tokenType,
            "refreshToken": refreshToken == nil ? "nil" : "<redacted>",
            "expiresIn": expiresIn as Any,
            "expiration": expiration as Any,
            "scope": scope as Any,
            "idToken": idToken == nil ? "nil" : "<redacted>",
            "instanceURL": instanceURL as Any,
            "idURL": idURL as Any,
        ], displayStyle: .struct)
    }
}
