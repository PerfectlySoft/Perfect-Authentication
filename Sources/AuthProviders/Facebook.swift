//
//  Facebook.swift
//  Turnstile
//
//  Created by Edward Jiang on 8/8/16.
//
//

import Foundation
import OAuth2
import PerfectHTTP

public struct FacebookConfig {
	public static var appid = ""
	public static var secret = ""

	/// Where should Facebook redirect to after Authorization
	public static var edpointAfterAuth = ""

	/// Where should the app redirect to after Authorization & Token Exchange
	public static var redirectAfterAuth = ""

	public init(){}
}

/**
 Facebook allows you to authenticate against Facebook for login purposes.
 */
public class Facebook: OAuth2 {
    /**
     Create a Facebook object. Uses the Client ID and Client Secret from the
     Facebook Developers Console.
     */
    public init(clientID: String, clientSecret: String) {
        let tokenURL = "https://graph.facebook.com/v2.3/oauth/access_token"
        let authorizationURL = URL(string: "https://www.facebook.com/dialog/oauth")!
        super.init(clientID: clientID, clientSecret: clientSecret, authorizationURL: authorizationURL, tokenURL: tokenURL)
    }


    private var appAccessToken: String {
        return clientID + "%7C" + clientSecret
    }
    

	public func getUserData(_ accessToken: String) -> [String: Any] {
		let fields = ["id","first_name","last_name","picture"]
		let url = "https://graph.facebook.com/v2.8/me?fields=\(fields.joined(separator: "%2C"))&access_token=\(accessToken)"
		let (_, data, _, _) = makeRequest(.get, url)

		var out = [String: Any]()

		if let n = data["id"] {
			out["userid"] = n as! String
		}
		if let n = data["first_name"] {
			out["first_name"] = n as! String
		}
		if let n = data["last_name"] {
			out["last_name"] = n as! String
		}

		out["picture"] = dig(mineFor: ["picture", "data", "url"], data: data) as! String


		return out
		//return data
	}

	public func exchange(request: HTTPRequest, state: String) throws -> OAuth2Token {
		return try exchange(request: request, state: state, redirectURL: FacebookConfig.edpointAfterAuth)
	}

	public func getLoginLink(state: String, scopes: [String] = []) -> String {
		return getLoginLink(redirectURL: FacebookConfig.edpointAfterAuth, state: state, scopes: scopes)
	}


	// Could be improved, I'm sure...
	func dig(mineFor: [String], data: [String: Any]) -> Any {
		if mineFor.count == 0 { return "" }
		for (key,value) in data {
			if key == mineFor[0] {
				var newMine = mineFor
				newMine.removeFirst()
				if newMine.count == 0 {
					return value
				} else if value is [String: Any] {
					return dig(mineFor: newMine, data: value as! [String : Any])
				}
			}
		}
		return ""
	}
}

