public struct OAuthUserProfile: Sendable {
    public let userid: String
    public let firstName: String?
    public let lastName: String?
    public let picture: String?
    public let accessToken: String
    public let refreshToken: String?
    public let loginType: String

    public init(
        userid: String,
        firstName: String? = nil,
        lastName: String? = nil,
        picture: String? = nil,
        accessToken: String,
        refreshToken: String? = nil,
        loginType: String
    ) {
        self.userid = userid
        self.firstName = firstName
        self.lastName = lastName
        self.picture = picture
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.loginType = loginType
    }
}
