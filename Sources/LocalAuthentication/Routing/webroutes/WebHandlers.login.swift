//
//  WebHandlers.login.swift
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

	// POST request for login
	static func login(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			var template = "views/msg" // where it goes to after
			if let i = request.session?.userid, !i.isEmpty { response.redirect(path: "/") }
			var context: [String : Any] = ["title": "Perfect Authentication Server"]
			context["csrfToken"] = request.session?.data["csrf"] as? String ?? ""

			if let u = request.param(name: "username"), !(u as String).isEmpty,
				let p = request.param(name: "password"), !(p as String).isEmpty {
				do {
					let acc = try Account.login(u, p)
					request.session?.userid = acc.id
					context["msg_title"] = "Login Successful."
					context["msg_body"] = ""
					response.redirect(path: "/")
				} catch {
					context["msg_title"] = "Login Error."
					context["msg_body"] = "Username or password incorrect"
					template = "views/index"
				}
			} else {
				context["msg_title"] = "Login Error."
				context["msg_body"] = "Username or password not supplied"
				template = "views/index"
			}
			response.render(template: template, context: context)
		}
	}

}
