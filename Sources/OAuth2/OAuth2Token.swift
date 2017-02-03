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
	public let instanceURL: String?
	public let idURL: String?
	public let scope: [String]?
	public let webToken: [String: Any]?

	public init(accessToken: String, tokenType: String, instanceURL: String? = nil, idURL: String? = nil, expiresIn: Int? = nil, refreshToken: String? = nil, scope: [String]? = nil, webToken: [String: Any]? = nil) {
		self.accessToken = accessToken
		self.tokenType = tokenType
		self.refreshToken = refreshToken
		self.expiration = expiresIn == nil ? nil : Date(timeIntervalSinceNow: Double(expiresIn!))
		self.scope = scope
		self.webToken = webToken
		self.instanceURL = instanceURL
		self.idURL = idURL
	}

	public convenience init?(json: [String: Any]) {
		guard let accessToken = json["access_token"] as? String else {
			return nil
		}
		var tokenType = "Bearer"
		if let tt = json["token_type"] {
			tokenType = tt as! String
		}
		let instanceURL: String? = json["instance_url"] as? String
		let idURL: String? = json["id"] as? String

		let expiresIn = json["expires_in"] as? Int
		let refreshToken: String? = json["refresh_token"] as? String
		let scope = (json["scope"] as? String)?.components(separatedBy: " ")
		let webToken = OAuth2Token.decodeWebToken(json: json)
		self.init(accessToken: accessToken, tokenType: tokenType, instanceURL: instanceURL, idURL: idURL, expiresIn: expiresIn, refreshToken: refreshToken, scope: scope, webToken: webToken)
	}

	private static func decodeWebToken(json: [String: Any]) -> [String: Any]? {
		var webToken: [String: Any]?

		/// Decode Google Json web token
		if let id = json["id_token"] as? String {
			let arr = id.components(separatedBy: ".")

			var content = arr[1] as String
			if content.characters.count % 4 != 0 {
				let padlen = 4 - content.characters.count % 4
				content += String(repeating: "=", count: padlen)
			}

			if let data = Data(base64Encoded: content, options: []),
				let str = String(data: data, encoding: String.Encoding.utf8) {
				do {
					webToken = try str.jsonDecode() as? [String : Any]
				} catch {
				}
			}
		}

		return webToken
	}
}
