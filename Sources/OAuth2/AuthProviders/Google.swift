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
import TurnstileCrypto
import PerfectSession

public struct GoogleConfig {
	public static var appid = ""
	public static var secret = ""

	/// Where should Google redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
Google allows you to authenticate against Google for login purposes.
*/
public class Google: OAuth2 {
	/**
	Create a Google object. Uses the Client ID and Client Secret from the
	Google Developers Console.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://www.googleapis.com/oauth2/v4/token"
		let authorizationURL = URL(string: "https://accounts.google.com/o/oauth2/auth")!
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}


	public func getUserData(_ accessToken: String) -> [String: Any] {
		let fields = ["family_name","given_name","id","picture"]
		let url = "https://www.googleapis.com/oauth2/v2/userinfo?fields=\(fields.joined(separator: "%2C"))&access_token=\(accessToken)"
		let (_, data, _, _) = makeRequest(.get, url)

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

	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: GoogleConfig.endpointAfterAuth)
	}

	public func getLoginLink(state: String, scopes: [String] = ["profile"]) -> String {
		return getLoginLink(redirectURL: GoogleConfig.endpointAfterAuth, state: state, scopes: scopes)
	}


	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
			do {
				guard let state = request.session?.data["state"] else {
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken

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
			response.redirect(path: GoogleConfig.redirectAfterAuth)
		}
	}





	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
			request.session?.data["state"] = rand.secureToken
			let fb = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["state"] as! String))
		}
	}


}

