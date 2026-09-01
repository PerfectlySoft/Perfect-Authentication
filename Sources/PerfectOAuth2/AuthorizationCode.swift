public struct AuthorizationCode: Sendable {
    public let code: String
    public let redirectURL: String

    public init(code: String, redirectURL: String) {
        self.code = code
        self.redirectURL = redirectURL
    }
}

public struct InvalidAuthorizationCodeError: Error, Sendable {
    public init() {}
    public let description = "The authorization code supplied could not be verified"
}
