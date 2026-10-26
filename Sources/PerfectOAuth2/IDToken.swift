import Foundation

/// Claim checks for an id_token received *directly from a provider's token endpoint over TLS*.
///
/// OpenID Connect Core §3.1.3.7 allows skipping the signature check in that case (the TLS server
/// authentication of the token endpoint stands in for it), but the issuer, audience and expiry must
/// still be checked. Never use this for an id_token from anywhere else (a browser, a query string, a
/// stored value): its claims can be forged.
struct IDTokenClaims: Sendable {
    let claims: JSONValue

    var subject: String? { claims["sub"]?.stringValue }

    static func validate(
        _ idToken: String,
        issuers: Set<String>,
        clientID: String,
        nonce: String? = nil,
        now: Date = Date(),
        leeway: TimeInterval = 300,
        maximumLifetime: TimeInterval = 86_400
    ) throws -> IDTokenClaims {
        let parts = idToken.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw OAuth2Error.invalidIDToken("not a compact JWS") }
        guard let payload = base64URLDecode(String(parts[1])),
              let json = try? JSONValue(data: payload), json.objectValue != nil else {
            throw OAuth2Error.invalidIDToken("payload is not base64url JSON")
        }
        guard let issuer = json["iss"]?.stringValue, issuers.contains(issuer) else {
            throw OAuth2Error.invalidIDToken("unexpected issuer")
        }
        let audiences: [String]
        if let single = json["aud"]?.stringValue {
            audiences = [single]
        } else if let many = json["aud"]?.arrayValue {
            audiences = many.compactMap(\.stringValue)
        } else {
            audiences = []
        }
        guard audiences.contains(clientID) else { throw OAuth2Error.invalidIDToken("audience is not this client") }
        if audiences.count > 1 || json["azp"] != nil {
            guard json["azp"]?.stringValue == clientID else {
                throw OAuth2Error.invalidIDToken("authorized party is not this client")
            }
        }
        // NumericDate (RFC 7519): JSON numbers only, not numeric strings.
        func numeric(_ value: JSONValue?) -> Double? {
            switch value {
            case .integer(let number)?: return Double(number)
            case .double(let number)? where number.isFinite: return number
            default: return nil
            }
        }
        guard let exp = numeric(json["exp"]) else { throw OAuth2Error.invalidIDToken("no numeric expiry") }
        guard let iat = numeric(json["iat"]) else { throw OAuth2Error.invalidIDToken("no numeric issue time") }
        let nowSeconds = now.timeIntervalSince1970
        guard nowSeconds < exp + leeway else { throw OAuth2Error.invalidIDToken("expired") }
        guard iat <= nowSeconds + leeway else { throw OAuth2Error.invalidIDToken("issued in the future") }
        guard exp - iat <= maximumLifetime else { throw OAuth2Error.invalidIDToken("lifetime too long") }
        guard let sub = json["sub"]?.stringValue,
              !sub.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw OAuth2Error.invalidIDToken("no subject")
        }
        if let nonce {
            guard let claimed = json["nonce"]?.stringValue, constantTimeEquals(claimed, nonce) else {
                throw OAuth2Error.invalidIDToken("nonce mismatch")
            }
        }
        return IDTokenClaims(claims: json)
    }
}
