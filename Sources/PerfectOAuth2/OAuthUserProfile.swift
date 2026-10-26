import Foundation

/// The signed-in user, as reported by the provider.
///
/// `userid` is never empty: the initializer throws `OAuth2Error.missingUserID` instead, so a failed
/// or partial profile fetch can't log everyone into one empty-id account. Key accounts on
/// `(loginType, userid)`. The description and mirror hide the token.
public struct OAuthUserProfile: Sendable, Equatable, CustomStringConvertible, CustomReflectable {
    /// The provider's stable user identifier (Google/LinkedIn/Slack `sub`, GitHub and Facebook `id`,
    /// Salesforce `user_id`).
    public let userid: String
    public let firstName: String?
    public let lastName: String?
    public let displayName: String?
    public let picture: String?
    /// The email address the provider returned, if any. Only treat it as belonging to the user when
    /// `emailVerified` is true.
    public let email: String?
    /// True only when the provider asserted that `email` is verified.
    public let emailVerified: Bool
    /// `"google"`, `"github"`, `"facebook"`, `"slack"`, `"linkedin"`, `"salesforce"`, or a custom
    /// provider's `loginType`.
    public let loginType: String
    public let token: OAuth2Token
    /// The provider's profile response, for fields not mapped above.
    public let raw: JSONValue

    public var accessToken: String { token.accessToken }
    public var refreshToken: String? { token.refreshToken }

    /// - Throws: `OAuth2Error.missingUserID` if `userid` is nil, empty or only whitespace.
    public init(
        userid: String?,
        firstName: String? = nil,
        lastName: String? = nil,
        displayName: String? = nil,
        picture: String? = nil,
        email: String? = nil,
        emailVerified: Bool = false,
        loginType: String,
        token: OAuth2Token,
        raw: JSONValue = .null
    ) throws {
        guard let userid, !userid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw OAuth2Error.missingUserID
        }
        func nonEmpty(_ value: String?) -> String? {
            guard let value, !value.isEmpty else { return nil }
            return value
        }
        self.userid = userid
        self.firstName = nonEmpty(firstName)
        self.lastName = nonEmpty(lastName)
        self.displayName = nonEmpty(displayName)
        self.picture = nonEmpty(picture)
        self.email = nonEmpty(email)
        self.emailVerified = emailVerified && nonEmpty(email) != nil
        self.loginType = loginType
        self.token = token
        self.raw = raw
    }

    public var description: String {
        "OAuthUserProfile(loginType: \(loginType), userid: \(userid), displayName: \(displayName ?? "nil"), token: <redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "userid": userid,
            "firstName": firstName as Any,
            "lastName": lastName as Any,
            "displayName": displayName as Any,
            "picture": picture as Any,
            "email": email as Any,
            "emailVerified": emailVerified,
            "loginType": loginType,
            "token": token,
            // Keys only: a provider response could carry a token-like value.
            "raw": raw.objectValue.map { "<JSON object: \($0.keys.sorted().joined(separator: ", "))>" } ?? "<JSON>",
        ], displayStyle: .struct)
    }
}
