//
//  Slack.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-31.
//
//


import Foundation
import PerfectHTTP
import PerfectSession

/// Slack configuration singleton
public struct SlackConfig {

	/// AppID obtained from registering app with Slack (Also known as Client ID)
	public static var appid = ""

	/// Secret associated with AppID (also known as Client Secret)
	public static var secret = ""

	/// Where should Slack redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
Slack allows you to authenticate against Slack for login purposes.
*/
public class Slack: OAuth2 {
	/**
	Create a Slack object. Uses the Client ID and Client Secret from the
	Slack Developers Console.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://slack.com/api/oauth.access"
		let authorizationURL = "https://slack.com/oauth/authorize"
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}

	/// After exchanging token, this function retrieves user information from Slack
	public func getUserData(_ accessToken: String) -> [String: Any] {
		let url = "https://slack.com/api/users.identity?token=\(accessToken)"
//		let (_, data, _, _) = makeRequest(.get, url)
		let data = makeRequest(.get, url)
		var out = [String: Any]()
		out["id"] = digIntoDictionary(mineFor: ["user", "id"], data: data) as! String
		let fullName = digIntoDictionary(mineFor: ["user", "name"], data: data) as! String
		let fullNameSplit = fullName.components(separatedBy: " ")
		if fullNameSplit.count > 0 {
			out["first_name"] = fullNameSplit.first
		}
		if fullNameSplit.count > 1 {
			out["last_name"] = fullNameSplit.last
		}
		out["picture"] = digIntoDictionary(mineFor: ["user", "image_192"], data: data) as! String

		return out
	}

	/// Slack-specific exchange function
	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: "\(SlackConfig.endpointAfterAuth)?session=\((request.session?.token)!)")
	}

	/// Slack-specific login link
	public func getLoginLink(state: String, request: HTTPRequest, scopes: [String] = ["identity.basic", "identity.avatar"]) -> String {
		return getLoginLink(redirectURL: "\(SlackConfig.endpointAfterAuth)?session=\((request.session?.token)!)", state: state, scopes: scopes)
	}

	/// Route handler for managing the response from the OAuth provider
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/auth/response/slack", "handler":Slack.authResponse]
	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = Slack(clientID: SlackConfig.appid, clientSecret: SlackConfig.secret)
			do {
				guard let state = request.session?.data["csrf"] else {
//					print("state issue: \(request.session?.data["state"])")
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken
				request.session?.data["refreshToken"] = t.refreshToken

				let userdata = fb.getUserData(t.accessToken)
				request.session?.data["loginType"] = "slack"

				if let i = userdata["id"] {
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
			response.redirect(path: SlackConfig.redirectAfterAuth, sessionid: (request.session?.token)!)
		}
	}

	/// Route handler for managing the sending of the user to the OAuth provider for approval/login
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/to/Slack", "handler":Slack.sendToProvider]
	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
//		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
//			request.session?.data["state"] = rand.secureToken
			let fb = Slack(clientID: SlackConfig.appid, clientSecret: SlackConfig.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["csrf"] as! String, request: request))
		}
	}
	
	
}

