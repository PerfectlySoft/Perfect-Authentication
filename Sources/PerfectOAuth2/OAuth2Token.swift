import Foundation

public class OAuth2Token: @unchecked Sendable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiration: Date?
    public let tokenType: String?
    public let instanceURL: String?
    public let idURL: String?
    public let scope: [String]?
    public let webToken: [String: Any]?

    public init(
        accessToken: String,
        tokenType: String,
        instanceURL: String? = nil,
        idURL: String? = nil,
        expiresIn: Int? = nil,
        refreshToken: String? = nil,
        scope: [String]? = nil,
        webToken: [String: Any]? = nil
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.expiration = expiresIn.map { Date(timeIntervalSinceNow: Double($0)) }
        self.scope = scope
        self.webToken = webToken
        self.instanceURL = instanceURL
        self.idURL = idURL
    }

    public convenience init?(json: [String: Any]) {
        guard let accessToken = json["access_token"] as? String else { return nil }
        let tokenType = json["token_type"] as? String ?? "Bearer"
        let instanceURL = json["instance_url"] as? String
        let idURL = json["id"] as? String
        let expiresIn = json["expires_in"] as? Int
        let refreshToken = json["refresh_token"] as? String
        let scope = (json["scope"] as? String)?.components(separatedBy: " ")
        let webToken = OAuth2Token.decodeWebToken(json: json)
        self.init(
            accessToken: accessToken,
            tokenType: tokenType,
            instanceURL: instanceURL,
            idURL: idURL,
            expiresIn: expiresIn,
            refreshToken: refreshToken,
            scope: scope,
            webToken: webToken
        )
    }

    private static func decodeWebToken(json: [String: Any]) -> [String: Any]? {
        guard let id = json["id_token"] as? String else { return nil }
        let parts = id.components(separatedBy: ".")
        guard parts.count >= 2 else { return nil }
        var content = parts[1]
        let padlen = (4 - content.count % 4) % 4
        content += String(repeating: "=", count: padlen)
        guard let data = Data(base64Encoded: content),
              let str = String(data: data, encoding: .utf8),
              let jsonData = str.data(using: .utf8),
              let decoded = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        else { return nil }
        return decoded
    }
}
