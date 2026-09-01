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
}
