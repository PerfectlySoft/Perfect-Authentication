//
//  JSONHandlers.logout.swift
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

	public static func logout(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			if let _ = request.session?.token {
				PostgresSessions().destroy(request, response)
				request.session = PerfectSession()
				response.request.session = PerfectSession()
			}
			_ = try? response.setBody(json: ["msg":"logout_success"])
			response.completed()
		}
	}

}
