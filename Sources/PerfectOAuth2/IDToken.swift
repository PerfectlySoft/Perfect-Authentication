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
        now: Date = Date(),
        leeway: TimeInterval = 300
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
        guard let exp = json["exp"]?.doubleValue else { throw OAuth2Error.invalidIDToken("no expiry") }
        guard now.timeIntervalSince1970 < exp + leeway else { throw OAuth2Error.invalidIDToken("expired") }
        if let iat = json["iat"]?.doubleValue, iat > now.timeIntervalSince1970 + leeway {
            throw OAuth2Error.invalidIDToken("issued in the future")
        }
        guard let sub = json["sub"]?.stringValue, !sub.isEmpty else {
            throw OAuth2Error.invalidIDToken("no subject")
        }
        return IDTokenClaims(claims: json)
    }
}
