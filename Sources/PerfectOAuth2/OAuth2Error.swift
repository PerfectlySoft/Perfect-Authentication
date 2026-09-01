public struct OAuth2Error: Error, Sendable {
    public let code: OAuth2ErrorCode
    public let description: String
    public let uri: String

    public init(code: OAuth2ErrorCode, description: String? = nil, uri: String? = nil) {
        self.code = code
        self.description = description ?? code.rawValue
        self.uri = uri ?? ""
    }

    init?(json: [String: Any]) {
        guard let errorCode = json["error"] as? String,
              let code = OAuth2ErrorCode(rawValue: errorCode) else { return nil }
        self.init(
            code: code,
            description: json["error_description"] as? String,
            uri: json["error_uri"] as? String
        )
    }

    public init?(dict: [String: String]) {
        guard let errorCode = dict["error"],
              let code = OAuth2ErrorCode(rawValue: errorCode) else { return nil }
        self.init(code: code, description: dict["error_description"], uri: dict["error_uri"])
    }
}

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

public struct InvalidAPIResponse: Error, Sendable {
    public let description = "Invalid API Response"
    public init() {}
}

public struct APIConnectionError: Error, Sendable {
    public let description = "Unable to connect to the external API"
    public init() {}
}

public struct InvalidInput: Error, Sendable {
    public let description = "Unexpected error occurred."
    public init() {}
}
