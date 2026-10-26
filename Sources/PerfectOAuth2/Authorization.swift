import Crypto
import Foundation

/// CSRF `state` generation and checking.
public enum AuthorizationState {
    /// The shortest stored state accepted: 32 characters (a UUID string, 16 random bytes in hex, or
    /// the 43-character value `generate()` returns).
    public static let minimumLength = 32
    /// The longest stored state accepted.
    public static let maximumLength = 512

    /// 32 bytes from `SystemRandomNumberGenerator`, base64url-encoded without padding (43 characters).
    public static func generate() -> String {
        randomBase64URL(byteCount: 32)
    }

    /// Checks the `state` returned to the callback against the one stored before redirecting.
    ///
    /// The stored value must be `minimumLength...maximumLength` characters, the returned one must be
    /// non-empty, and they are compared in constant time (only the lengths can leak).
    /// - Throws: `OAuth2Error.invalidState` for an unusable stored value, otherwise
    ///   `OAuth2Error.stateMismatch`.
    public static func verify(returned: String?, expected: String) throws {
        let length = expected.utf8.count
        guard length >= minimumLength else {
            throw OAuth2Error.invalidState("stored state must be at least \(minimumLength) characters")
        }
        guard length <= maximumLength else {
            throw OAuth2Error.invalidState("stored state must be at most \(maximumLength) characters")
        }
        guard let returned, !returned.isEmpty, constantTimeEquals(returned, expected) else {
            throw OAuth2Error.stateMismatch
        }
    }

    static func validateStored(_ state: String) throws {
        let length = state.utf8.count
        guard length >= minimumLength, length <= maximumLength else {
            throw OAuth2Error.invalidState(
                "state must be \(minimumLength) to \(maximumLength) characters; use AuthorizationState.generate()"
            )
        }
    }
}

/// PKCE (RFC 7636) with the S256 method.
public enum PKCE {
    /// A code verifier: 32 random bytes, base64url-encoded (43 characters, the RFC 7636 §4.1 minimum
    /// length and the encoding its appendix uses).
    public static func generateVerifier() -> String {
        randomBase64URL(byteCount: 32)
    }

    /// True for an RFC 7636 §4.1 verifier: 43 to 128 characters of `[A-Za-z0-9-._~]`.
    public static func isValidVerifier(_ verifier: String) -> Bool {
        (43...128).contains(verifier.utf8.count) && verifier.utf8.allSatisfy(isUnreserved)
    }

    /// `BASE64URL(SHA256(ASCII(verifier)))`, RFC 7636 §4.2.
    public static func challenge(for verifier: String) -> String {
        base64URLEncode(Data(SHA256.hash(data: Data(verifier.utf8))))
    }
}

/// What to keep in the server-side session between redirecting the user and handling the callback.
///
/// It's `Codable` so it can be stored as JSON. **The JSON contains the PKCE code verifier and the
/// state in clear**: keep it server-side (a server-side session store, not a client-readable cookie),
/// under a key per provider, and delete it when the callback arrives, so each one is used once.
///
/// It is bound to the client that created it: `exchange` refuses a pending authorization from another
/// provider or client ID, one older than `OAuth2ClientConfiguration.pendingAuthorizationMaxAge`, one
/// whose redirect URL isn't the configured one, or one already completed by this `OAuth2` instance.
public struct PendingAuthorization: Sendable, Codable, Equatable, CustomStringConvertible, CustomReflectable {
    public let state: String
    /// The PKCE code verifier, or nil when PKCE is disabled for this provider.
    public let codeVerifier: String?
    /// The `redirect_uri` sent in the authorization request; sent again, unchanged, on exchange.
    public let redirectURL: URL
    /// The OpenID Connect nonce sent in the authorization request (Google without PKCE), if any.
    public let nonce: String?
    /// The token endpoint and client ID of the `OAuth2` that created it.
    public let tokenURL: URL
    public let clientID: String
    public let createdAt: Date

    public init(
        state: String,
        codeVerifier: String?,
        redirectURL: URL,
        nonce: String? = nil,
        tokenURL: URL,
        clientID: String,
        createdAt: Date = Date()
    ) {
        self.state = state
        self.codeVerifier = codeVerifier
        self.redirectURL = redirectURL
        self.nonce = nonce
        self.tokenURL = tokenURL
        self.clientID = clientID
        self.createdAt = createdAt
    }

    public var description: String {
        "PendingAuthorization(state: <redacted>, codeVerifier: \(codeVerifier == nil ? "nil" : "<redacted>"), redirectURL: \(redirectURL), tokenURL: \(tokenURL), clientID: \(clientID), createdAt: \(createdAt))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "state": "<redacted>",
            "codeVerifier": codeVerifier == nil ? "nil" : "<redacted>",
            "redirectURL": redirectURL,
            "nonce": nonce == nil ? "nil" : "<redacted>",
            "tokenURL": tokenURL,
            "clientID": clientID,
            "createdAt": createdAt,
        ], displayStyle: .struct)
    }
}

/// A login link plus what to store for the callback.
public struct AuthorizationRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Redirect the user's browser here.
    public let url: URL
    /// Store this in the server-side session and pass it to `completeAuthorization`.
    public let pending: PendingAuthorization

    public var description: String { "AuthorizationRequest(url: <login link>, pending: \(pending))" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["url": "<login link>", "pending": pending], displayStyle: .struct)
    }
}

/// What the provider sent back to the redirect URL.
///
/// Its description, `dump` and `Mirror` hide `code` and `state`.
public struct AuthorizationCallback: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let code: String?
    public let state: String?
    public let error: OAuth2ErrorResponse?

    public init(code: String?, state: String?, error: OAuth2ErrorResponse? = nil) {
        self.code = code
        self.state = state
        self.error = error
    }

    /// Reads `code`, `state`, `error`, `error_description` and `error_uri` from query items.
    /// A repeated parameter makes the callback unusable: `code` or `state` comes back nil, and a
    /// repeated `error` becomes an `invalid_request` error.
    public init(queryItems: [URLQueryItem]) {
        func single(_ name: String) -> String? {
            let values = queryItems.filter { $0.name == name }
            return values.count == 1 ? values[0].value : nil
        }
        code = single("code")
        state = single("state")
        if queryItems.filter({ $0.name == "error" }).count > 1 {
            // Ambiguous: never fall through to the code.
            error = OAuth2ErrorResponse(code: "invalid_request", errorDescription: "repeated error parameter")
        } else if let errorCode = single("error") {
            error = OAuth2ErrorResponse(
                code: errorCode,
                errorDescription: single("error_description"),
                errorURI: single("error_uri")
            )
        } else {
            error = nil
        }
    }

    /// Reads the callback parameters from the request URL the provider redirected to.
    public init(url: URL) {
        self.init(queryItems: URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? [])
    }

    public var description: String {
        "AuthorizationCallback(code: \(code == nil ? "nil" : "<redacted>"), state: \(state == nil ? "nil" : "<redacted>"), error: \(error.map { "\($0)" } ?? "nil"))"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: [
            "code": code == nil ? "nil" : "<redacted>",
            "state": state == nil ? "nil" : "<redacted>",
            "error": error as Any,
        ], displayStyle: .struct)
    }
}

// MARK: - Encoding helpers

func isUnreserved(_ byte: UInt8) -> Bool {
    switch byte {
    case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
         UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."),
         UInt8(ascii: "_"), UInt8(ascii: "~"):
        return true
    default:
        return false
    }
}

func randomBase64URL(byteCount: Int) -> String {
    var generator = SystemRandomNumberGenerator()
    var bytes = [UInt8](repeating: 0, count: byteCount)
    for index in bytes.indices { bytes[index] = generator.next() }
    return base64URLEncode(Data(bytes))
}

func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Decodes base64url (RFC 4648 §5), with or without padding. Rejects standard-alphabet `+` and `/`.
func base64URLDecode(_ text: String) -> Data? {
    guard !text.contains("+"), !text.contains("/") else { return nil }
    var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 = base64.replacingOccurrences(of: "=", with: "")
    if base64.count % 4 == 1 { return nil }
    base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
    return Data(base64Encoded: base64)
}

/// Compares two strings' UTF-8 bytes in time that depends only on their lengths.
func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8), right = Array(rhs.utf8)
    var difference = left.count ^ right.count
    for index in 0..<max(left.count, right.count) {
        let a = index < left.count ? left[index] : 0
        let b = index < right.count ? right[index] : 0
        difference |= Int(a ^ b)
    }
    return difference == 0
}

private let formValueAllowed = CharacterSet(
    charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

/// Percent-encodes everything but unreserved characters (the encoding `formEncode` uses).
func percentEncodeAll(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: formValueAllowed) ?? value
}

/// `application/x-www-form-urlencoded` body, keys in the given order, every reserved byte encoded.
func formEncode(_ fields: [(String, String)]) -> Data {
    let text = fields.map { key, value in
        let k = key.addingPercentEncoding(withAllowedCharacters: formValueAllowed) ?? ""
        let v = value.addingPercentEncoding(withAllowedCharacters: formValueAllowed) ?? ""
        return "\(k)=\(v)"
    }.joined(separator: "&")
    return Data(text.utf8)
}

/// Appends query items to a URL with `URLComponents`, encoding `+` too (URLComponents leaves it
/// alone, and many servers read a literal `+` in a query as a space).
func appendingQueryItems(_ items: [URLQueryItem], to url: URL) throws -> URL {
    guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        throw OAuth2Error.invalidConfiguration("unparseable URL")
    }
    var existing = components.percentEncodedQueryItems ?? []
    for item in items {
        let name = item.name.addingPercentEncoding(withAllowedCharacters: formValueAllowed) ?? ""
        let value = item.value?.addingPercentEncoding(withAllowedCharacters: formValueAllowed)
        existing.append(URLQueryItem(name: name, value: value))
    }
    components.percentEncodedQueryItems = existing.isEmpty ? nil : existing
    guard let result = components.url else { throw OAuth2Error.invalidConfiguration("unbuildable URL") }
    return result
}

func isLoopback(host: String?) -> Bool {
    // Exactly these names; not *.localhost (resolver-dependent) or other 127/8 addresses.
    guard let host = host?.lowercased() else { return false }
    return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

/// HTTPS, or HTTP to a loopback host (for local testing).
func requireSecure(_ url: URL, _ what: String) throws {
    guard url.host?.isEmpty == false else { throw OAuth2Error.insecureURL("\(what) has no host") }
    switch url.scheme?.lowercased() {
    case "https": return
    case "http" where isLoopback(host: url.host): return
    default: throw OAuth2Error.insecureURL("\(what) must use https")
    }
}
