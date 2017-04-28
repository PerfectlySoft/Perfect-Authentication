//
//  JSONHandler.session.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-04-26.
//
//

import PerfectHTTP
import PerfectSession
import PerfectCrypto
import PerfectSessionPostgreSQL


extension JSONHandlers {

	// SESSION request
	// Returns the SessionID and CSRF Token
	// Note that if an "Authorization" Header with a Bearer token is sent
	// this will echo the same session token and provide the Session's CSRF token
	static func session(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			_ = try? response.setBody(json: ["sessionid":request.session?.token, "csrf": request.session?.data["csrf"]])
			response.completed()
		}
	}

}
