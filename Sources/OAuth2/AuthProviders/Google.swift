//
//  Google.swift
//	Perfect Authentication / Auth Providers
//  Inspired by Turnstile (Edward Jiang)
//
//  Created by Jonathan Guthrie on 2017-01-25.
//
//
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//
// https://developers.google.com/identity/protocols/OAuth2

import Foundation
import PerfectHTTP
import PerfectSession

/// Google configuration singleton
public struct GoogleConfig {

	/// AppID obtained from registering app with Google (Also known as Client ID)
	public static var appid = ""

	/// Secret associated with AppID (also known as Client Secret)
	public static var secret = ""

	/// Where should Google redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	/// Domain restriction if needed
	public static var restrictedDomain: String?

	public init(){}
}

/**
Google allows you to authenticate against Google for login purposes.
*/
public class Google: OAuth2 {
	/**
	Create a Google object. Uses the Client ID and Client Secret obtained when registering the application.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://www.googleapis.com/oauth2/v4/token"
		let authorizationURL = "https://accounts.google.com/o/oauth2/auth"
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}


	/// After exchanging token, this function retrieves user information from Google
	public func getUserData(_ accessToken: String) -> [String: Any] {
		let fields = ["family_name","given_name","id","picture"]
		let url = "https://www.googleapis.com/oauth2/v2/userinfo?fields=\(fields.joined(separator: "%2C"))&access_token=\(accessToken)"
//		let (_, data, _, _) = makeRequest(.get, url)
		let data = makeRequest(.get, url)

		var out = [String: Any]()

		if let n = data["id"] {
			out["userid"] = n as! String
		}
		if let n = data["given_name"] {
			out["first_name"] = n as! String
		}
		if let n = data["family_name"] {
			out["last_name"] = n as! String
		}
		if let n = data["picture"] {
			out["picture"] = n as! String
		}

		return out
	}

	/// Google-specific exchange function
	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		let token = try exchange(request: request, state: state, redirectURL: "\(GoogleConfig.endpointAfterAuth)?session=\((request.session?.token)!)")

		if let domain = GoogleConfig.restrictedDomain {
			guard let hd = token.webToken?["hd"] as? String, hd == domain else {
				throw OAuth2Error(code: .unsupportedResponseType)
			}
		}

		return token
	}

	/// Google-specific login link
	public func getLoginLink(state: String, request: HTTPRequest, scopes: [String] = ["profile"]) -> String {
		var url = getLoginLink(redirectURL: "\(GoogleConfig.endpointAfterAuth)?session=\((request.session?.token)!)", state: state, scopes: scopes)
		if let domain = GoogleConfig.restrictedDomain {
			url += "&hd=\(domain)"
		}
		return url
	}


	/// Route handler for managing the response from the OAuth provider
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/auth/response/facebook", "handler":Facebook.authResponse]
	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
			do {
				guard let state = request.session?.data["csrf"] else {
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken
				request.session?.data["refreshToken"] = t.refreshToken

				let userdata = fb.getUserData(t.accessToken)

				request.session?.data["loginType"] = "google"


				if let i = userdata["userid"] {
					request.session?.userid = i as! String
				}
				if let i = userdata["first_name"] {
					request.session?.data["firstName"] = i as! String
				}
				if let i = userdata["last_name"] {
					request.session?.data["lastName"] = i as! String
				}
				if let i = userdata["picture"] {
					request.session?.data["picture"] = i as! String
				}

			} catch {
				print(error)
			}
			response.redirect(path: GoogleConfig.redirectAfterAuth, sessionid: (request.session?.token)!)
		}
	}





	/// Route handler for managing the sending of the user to the OAuth provider for approval/login
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/to/google", "handler":Google.sendToProvider]
	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
//		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
//			request.session?.data["state"] = rand.secureToken
			let fb = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["csrf"] as! String, request: request))
		}
	}


}

