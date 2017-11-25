//
//  SalesForce.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-31.
//
//

import Foundation
import PerfectHTTP
import PerfectSession

/// SalesForce configuration singleton
public struct SalesForceConfig {

	/// AppID obtained from registering app with SalesForce (Also known as Client ID)
	public static var appid = ""

	/// Secret associated with AppID (also known as Client Secret)
	public static var secret = ""

	/// Where should SalesForce redirect to after Authorization
	public static var endpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
SalesForce allows you to authenticate against SalesForce for login purposes.
*/
public class SalesForce: OAuth2 {
	/**
	Create a SalesForce object. Uses the Client ID and Client Secret from the
	SalesForce Developers Console.
	*/
	public init(clientID: String, clientSecret: String) {
		let tokenURL = "https://login.salesforce.com/services/oauth2/token"
		let authorizationURL = "https://login.salesforce.com/services/oauth2/authorize"
		super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
	}


	private var appAccessToken: String {
		return clientID + "%7C" + clientSecret
	}

	/// After exchanging token, this function retrieves user information from SalesForce
	public func getUserData(_ accessToken: String, _ idURL: String) -> [String: Any] {
		let url = idURL
//		let (_, data, _, _) = makeRequest(.get, url, bearerToken: accessToken)
		let data = makeRequest(.get, url, bearerToken: accessToken)

		var out = [String: Any]()
		if let n = data["user_id"] {
			out["userid"] = n as! String
		}
		if let n = data["first_name"] {
			out["first_name"] = n as! String
		}
		if let n = data["last_name"] {
			out["last_name"] = n as! String
		}
		out["picture"] = digIntoDictionary(mineFor: ["photos", "picture"], data: data) as! String

		//		["asserted_user": true, "display_name": "Jonathan Guthrie", "is_app_installed": true, "addr_street": PerfectLib.JSONConvertibleNull(), "language": "en_US", "active": true, "addr_city": PerfectLib.JSONConvertibleNull(), "last_name": "Guthrie", "id": "https://login.salesforce.com/id/00D41000002lDGEEA2/00541000002W2n0AAC", "timezone": "America/New_York", "addr_country": "CA", "urls": ["metadata": "https://na35.salesforce.com/services/Soap/m/{version}/00D41000002lDGE", "search": "https://na35.salesforce.com/services/data/v{version}/search/", "users": "https://na35.salesforce.com/services/data/v{version}/chatter/users", "feed_items": "https://na35.salesforce.com/services/data/v{version}/chatter/feed-items", "feed_elements": "https://na35.salesforce.com/services/data/v{version}/chatter/feed-elements", "query": "https://na35.salesforce.com/services/data/v{version}/query/", "enterprise": "https://na35.salesforce.com/services/Soap/c/{version}/00D41000002lDGE", "sobjects": "https://na35.salesforce.com/services/data/v{version}/sobjects/", "recent": "https://na35.salesforce.com/services/data/v{version}/recent/", "rest": "https://na35.salesforce.com/services/data/v{version}/", "groups": "https://na35.salesforce.com/services/data/v{version}/chatter/groups", "feeds": "https://na35.salesforce.com/services/data/v{version}/chatter/feeds", "profile": "https://na35.salesforce.com/00541000002W2n0AAC", "partner": "https://na35.salesforce.com/services/Soap/u/{version}/00D41000002lDGE"], "utcOffset": -18000000, "mobile_phone_verified": false, "organization_id": "00D41000002lDGEEA2", "nick_name": "jono", "email_verified": true, "email": "jono@perfect.org", "photos": ["picture": "https://c.na35.content.force.com/profilephoto/005/F", "thumbnail": "https://c.na35.content.force.com/profilephoto/005/T"], "username": "jono@perfect.org", "addr_zip": PerfectLib.JSONConvertibleNull(), "addr_state": PerfectLib.JSONConvertibleNull(), "status": ["created_date": PerfectLib.JSONConvertibleNull(), "body": PerfectLib.JSONConvertibleNull()], "locale": "en_US", "mobile_phone": PerfectLib.JSONConvertibleNull(), "last_modified_date": "2017-01-31T21:19:51.000+0000", "first_name": "Jonathan", "user_type": "STANDARD", "user_id": "00541000002W2n0AAC"]

		return out
	}

	/// SalesForce-specific exchange function
	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: "\(SalesForceConfig.endpointAfterAuth)?session=\((request.session?.token)!)")
	}

	/// SalesForce-specific login link
	public func getLoginLink(state: String, request: HTTPRequest, scopes: [String] = ["id"]) -> String {
		return getLoginLink(redirectURL: "\(SalesForceConfig.endpointAfterAuth)?session=\((request.session?.token)!)", state: state, scopes: scopes)
	}

	/// Route handler for managing the response from the OAuth provider
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/auth/response/slack", "handler":SalesForce.authResponse]
	public static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = SalesForce(clientID: SalesForceConfig.appid, clientSecret: SalesForceConfig.secret)
			do {
				guard let state = request.session?.data["csrf"] else {
//					print("state issue: \(request.session?.data["state"])")
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken
				request.session?.data["refreshToken"] = t.refreshToken

				let userdata = fb.getUserData(t.accessToken, t.idURL!)
				request.session?.data["loginType"] = "salesforce"

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
			response.redirect(path: SalesForceConfig.redirectAfterAuth)
		}
	}

	/// Route handler for managing the sending of the user to the OAuth provider for approval/login
	/// Route definition would be in the form
	/// ["method":"get", "uri":"/to/salesforce", "handler":SalesForce.sendToProvider]
	public static func sendToProvider(data: [String:Any]) throws -> RequestHandler {
//		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
//			request.session?.data["state"] = rand.secureToken
			let fb = SalesForce(clientID: SalesForceConfig.appid, clientSecret: SalesForceConfig.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["csrf"] as! String, request: request))
		}
	}
	
	
}

