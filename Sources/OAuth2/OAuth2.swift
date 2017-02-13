//
//  OAuth2.swift
//  Based on Turnstile's oAuth2
//
//  Created by Edward Jiang on 8/7/16.
//
//	Modified by Jonathan Guthrie 18 Jan 2017
//	Intended to work more independantly of Turnstile

import Foundation
import PerfectHTTP

/**
 OAuth 2 represents the base API Client for an OAuth 2 server that implements the
 authorization code grant type. This is the typical redirect based login flow.
 
 Since OAuth doesn't define token validation, implementing it is up to a subclass.
 */
open class OAuth2 {
    /// The Client ID for the OAuth 2 Server
    public let clientID: String
    
    /// The Client Secret for the OAuth 2 Server
    public let clientSecret: String
    
    /// The Authorization Endpoint of the OAuth 2 Server
    public let authorizationURL: String
    
    /// The Token Endpoint of the OAuth 2 Server
    public let tokenURL: String
    
    /// Creates the OAuth 2 client
    public init(clientID: String, clientSecret: String, authorizationURL: String, tokenURL: String) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.authorizationURL = authorizationURL
        self.tokenURL = tokenURL
    }
    
    
    /// Gets the login link for the OAuth 2 server. Redirect the end user to this URL
    ///
    /// - parameter redirectURL: The URL for the server to redirect the user back to after login.
    ///     You will need to configure this in the admin console for the OAuth provider's site.
    /// - parameter state:       A randomly generated string to prevent CSRF attacks.
    ///     Verify this when validating the Authorization Code
    /// - parameter scopes:      A list of OAuth scopes you'd like the user to grant
    open func getLoginLink(redirectURL: String, state: String, scopes: [String] = []) -> String {
		var url = "\(authorizationURL)?response_type=code"
		url += "&client_id=\(clientID.stringByEncodingURL)"
		url += "&redirect_uri=\(redirectURL.stringByEncodingURL)"
		url += "&state=\(state.stringByEncodingURL)"
		url += "&scope=\((scopes.joined(separator: " ")).stringByEncodingURL)"
		return url
    }
    
    
    /// Exchanges an authorization code for an access token
    /// - throws: InvalidAuthorizationCodeError() if the Authorization Code could not be validated
    /// - throws: APIConnectionError() if we cannot connect to the OAuth server
    /// - throws: InvalidAPIResponse() if the server does not respond in a way we expect
    open func exchange(authorizationCode: AuthorizationCode) throws -> OAuth2Token {
        let postBody = ["grant_type": "authorization_code",
                        "client_id": clientID,
                        "client_secret": clientSecret,
                        "redirect_uri": authorizationCode.redirectURL,
                        "code": authorizationCode.code]
//		let (_, data, _, _) = makeRequest(.post, tokenURL, body: urlencode(dict: postBody), encoding: "form")
		let data = makeRequest(.post, tokenURL, body: urlencode(dict: postBody), encoding: "form")
        guard let token = OAuth2Token(json: data) else {
            if let error = OAuth2Error(json: data) {
                throw error
            } else {
                throw InvalidAPIResponse()
            }
        }
        return token
    }
    
    /// Parses a URL and exchanges the OAuth 2 access token and exchanges it for an access token
    /// - throws: InvalidAuthorizationCodeError() if the Authorization Code could not be validated
    /// - throws: APIConnectionError() if we cannot connect to the OAuth server
    /// - throws: InvalidAPIResponse() if the server does not respond in a way we expect
    /// - throws: OAuth2Error() if the oauth server calls back with an error
	open func exchange(request: HTTPRequest, state: String, redirectURL: String) throws -> OAuth2Token {
		//request.param(name: "state") == state
		guard let code = request.param(name: "code")
             else {
				print("Where's the code?")
                throw InvalidAPIResponse()
        }
        return try exchange(authorizationCode: AuthorizationCode(code: code, redirectURL: redirectURL))
    }
    
    // TODO: add refresh token support
}

extension URLComponents {
    var queryDictionary: [String: String] {

        var result = [String: String]()
        
        guard let components = query?.components(separatedBy: "&") else {
            return result
        }
        
        components.forEach { component in
            let queryPair = component.components(separatedBy: "=")
            
            if queryPair.count == 2 {
                result[queryPair[0]] = queryPair[1]
            } else {
                result[queryPair[0]] = ""
            }
        }
        return result
    }
}

extension URLComponents {
    mutating func setQueryItems(dict: [String: String]) {
        query = dict.map { (key, value) in
            return key + "=" + value
            }.joined(separator: "&")
    }
}
