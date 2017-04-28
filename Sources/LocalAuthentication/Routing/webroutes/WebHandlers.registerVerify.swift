//
//  WebHandlers.registerVerify.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-04-26.
//
//

import PerfectHTTP
import PerfectSession
import PerfectCrypto
import PerfectSessionPostgreSQL


extension WebHandlers {


	// Verify GET
	static func registerVerify(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let t = request.session?.data["csrf"] as? String ?? ""
			if let i = request.session?.userid, !i.isEmpty { response.redirect(path: "/") }
			var context: [String : Any] = ["title": "Perfect Authentication Server"]

			if let v = request.urlVariables["passvalidation"], !(v as String).isEmpty {

				let acc = Account(validation: v)

				if acc.id.isEmpty {
					context["msg_title"] = "Account Validation Error."
					context["msg_body"] = ""
					response.render(template: "views/msg", context: context)
					return
				} else {
					context["passvalidation"] = v
					context["csrfToken"] = t
					response.render(template: "views/registerComplete", context: context)
				}
			} else {
				context["msg_title"] = "Account Validation Error."
				context["msg_body"] = "Code not found."
				response.render(template: "views/msg", context: context)
			}
		}
	}
	
	

}
