//
//  WebHandlers.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-02-06.
//
//

import PerfectHTTP
import PerfectSession
import PerfectCrypto
import PerfectSessionPostgreSQL


class WebHandlers {

	static func main(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			var context: [String : Any] = ["title": "Perfect Authentication Server"]
			if let i = request.session?.userid, !i.isEmpty { context["authenticated"] = true }
			context["csrfToken"] = request.session?.data["csrf"] as? String ?? ""
			response.render(template: "views/index", context: context)
		}
	}




}
