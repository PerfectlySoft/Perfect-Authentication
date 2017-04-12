//
//  GitHub.swift
//	Perfect Authentication / Auth Providers
//  Inspired by Turnstile (Edward Jiang)
//
//  Created by Jonathan Guthrie on 2017-01-24
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

import Foundation
import PerfectHTTP
import PerfectSession

/// GitHub configuration singleton
public struct GitHubConfig {

	/// AppID obtained from registering app with GitHub (Also known as Client ID)
	public static var appid = ""

	/// Secret associated with AppID (also known as Client Secret)
	public static var secret = ""

	/// Where should Facebook redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
GitHub allows you to authenticate against GitHub for login purposes.
*/
public class GitHub: OAuth2 {
	/**
	Create a GitHub object. Uses the Client ID and Client Secret obtained when registering the application.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://github.com/login/oauth/access_token"
		let authorizationURL = "https://github.com/login/oauth/authorize"
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}


	/// After exchanging token, this function retrieves user information from GitHub
	public func getUserData(_ accessToken: String) -> [String: Any] {
		let url = "https://api.github.com/user?access_token=\(accessToken)"
//		let (_, data, _, _) = makeRequest(.get, url)
		let data = makeRequest(.get, url)

		var out = [String: Any]()

		if let n = data["id"] {
			out["userid"] = "\(n)"
		}
		if let n = data["name"] {
			let nn = n as! String
			let nnn = nn.split(" ")
			if nnn.count > 0 {
				out["first_name"] = nnn.first
			}
			if nnn.count > 1 {
				out["last_name"] = nnn.last
			}
		}
		if let n = data["avatar_url"] {
			out["picture"] = n as! String
		}

		return out
	}

	/// GitHub-specific exchange function
	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: "\(GitHubConfig.endpointAfterAuth)?session=\((request.session?.token)!)")
	}

	/// GitHub-specific login link
	public func getLoginLink(state: String, request: HTTPRequest, scopes: [String] = []) -> String {
		return getLoginLink(redirectURL: "\(GitHubConfig.endpointAfterAuth)?session=\((request.session?.token)!)", state: state, scopes: scopes)
	}



	/// Route handler for managing the response from the OAuth provider
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/auth/response/github", "handler":GitHub.authResponse]
	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = GitHub(clientID: GitHubConfig.appid, clientSecret: GitHubConfig.secret)
			do {
				guard let state = request.session?.data["csrf"] else {
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken
				request.session?.data["refreshToken"] = t.refreshToken

				let userdata = fb.getUserData(t.accessToken)

				request.session?.data["loginType"] = "github"


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
			response.redirect(path: GitHubConfig.redirectAfterAuth, sessionid: (request.session?.token)!)
		}
	}





	/// Route handler for managing the sending of the user to the OAuth provider for approval/login
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/to/github", "handler":GitHub.sendToProvider]
	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
//		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
//			request.session?.data["state"] = rand.secureToken
			let tw = GitHub(clientID: GitHubConfig.appid, clientSecret: GitHubConfig.secret)
			response.redirect(path: tw.getLoginLink(state: request.session?.data["csrf"] as! String, request: request, scopes: ["user"]))
		}
	}
	
	
}

