//
//  OAuth2Token.swift
//  Based on Turnstile's oAuth2
//
//  Created by Edward Jiang on 8/13/16.
//
//	Modified by Jonathan Guthrie 18 Jan 2017
//	Intended to work more independantly of Turnstile


import Foundation

/**
 Represents an OAuth 2 Token
 */
public class OAuth2Token {
    public let accessToken: String
    public let refreshToken: String?
    public let expiration: Date?
    public let tokenType: String?
    public let scope: [String]?
    
    public init(accessToken: String, tokenType: String, expiresIn: Int? = nil, refreshToken: String? = nil, scope: [String]? = nil) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.expiration = expiresIn == nil ? nil : Date(timeIntervalSinceNow: Double(expiresIn!))
        self.scope = scope
    }
    
    public convenience init?(json: [String: Any]) {
        guard let accessToken = json["access_token"] as? String,
            let tokenType = json["token_type"] as? String else {
            return nil
        }
        
        let expiresIn = json["expires_in"] as? Int
        let refreshToken: String? = json["refresh_token"] as? String
        let scope = (json["scope"] as? String)?.components(separatedBy: " ")
        self.init(accessToken: accessToken, tokenType: tokenType, expiresIn: expiresIn, refreshToken: refreshToken, scope: scope)
    }
}
