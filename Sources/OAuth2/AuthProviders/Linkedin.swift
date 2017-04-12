//
//  Linkedin.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-31.
//
//


import Foundation
import PerfectHTTP
import PerfectSession

/// Linkedin configuration singleton
public struct LinkedinConfig {

	/// AppID obtained from registering app with Linkedin (Also known as Client ID)
	public static var appid = ""

	/// Secret associated with AppID (also known as Client Secret)
	public static var secret = ""

	/// Where should Linkedin redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
Linkedin allows you to authenticate against Linkedin for login purposes.
*/
public class Linkedin: OAuth2 {
	/**
	Create a Linkedin object. Uses the Client ID and Client Secret from the
	Linkedin Developers Console.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://www.linkedin.com/oauth/v2/accessToken"
		let authorizationURL = "https://www.linkedin.com/oauth/v2/authorization"
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}

	/// After exchanging token, this function retrieves user information from Linkedin
	public func getUserData(_ accessToken: String) -> [String: Any] {
		let url = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url)?format=json"
//		let (_, data, _, _) = makeRequest(.get, url, bearerToken: accessToken)
		let data = makeRequest(.get, url, bearerToken: accessToken)

		var out = [String: Any]()

		if let n = data["id"] {
			out["userid"] = n as! String
		}
		if let n = data["firstName"] {
			out["first_name"] = n as! String
		}
		if let n = data["lastName"] {
			out["last_name"] = n as! String
		}
		if let n = data["pictureUrl"] {
			out["picture"] = n as! String
		}

		return out
	}

	/// Linkedin-specific exchange function
	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: LinkedinConfig.endpointAfterAuth)
	}

	/// Linkedin-specific login link
	public func getLoginLink(state: String, request: HTTPRequest, scopes: [String] = ["r_basicprofile"]) -> String {
		return getLoginLink(redirectURL: LinkedinConfig.endpointAfterAuth, state: state, scopes: scopes)
	}

	/// Route handler for managing the response from the OAuth provider
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/auth/response/linkedin", "handler":Linkedin.authResponse]
	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = Linkedin(clientID: LinkedinConfig.appid, clientSecret: LinkedinConfig.secret)
			do {
				guard let state = request.session?.data["csrf"] else {
//					print("state issue: \(request.session?.data["csrf"])")
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken
				request.session?.data["refreshToken"] = t.refreshToken

				let userdata = fb.getUserData(t.accessToken)

				request.session?.data["loginType"] = "linkedin"


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
			response.redirect(path: LinkedinConfig.redirectAfterAuth, sessionid: (request.session?.token)!)
		}
	}

	/// Route handler for managing the sending of the user to the OAuth provider for approval/login
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/to/linkedin", "handler":Linkedin.sendToProvider]
	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
//		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
//			request.session?.data["state"] = rand.secureToken
			let fb = Linkedin(clientID: LinkedinConfig.appid, clientSecret: LinkedinConfig.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["csrf"] as! String, request: request))
		}
	}
	
	
}

