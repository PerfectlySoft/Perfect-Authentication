//
//  WebHandlers.register.swift
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

	// Register GET - displays form
	public static func register(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			if let i = request.session?.userid, !i.isEmpty { response.redirect(path: "/") }
			let t = request.session?.data["csrf"] as? String ?? ""

			var context: [String : Any] = ["title": "Perfect Authentication Server"]
			context["csrfToken"] = t
			response.render(template: "views/register", context: context)
		}
	}


	// POST request for register form
	public static func registerPost(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			if let i = request.session?.userid, !i.isEmpty { response.redirect(path: "/") }
			var context: [String : Any] = ["title": "Perfect Authentication Server"]

			if let u = request.param(name: "username"), !(u as String).isEmpty,
				let e = request.param(name: "email"), !(e as String).isEmpty {
				let err = Account.register(u, e, .provisional, baseURL: AuthenticationVariables.baseURL)
				if err != .noError {
					print(err)
					context["msg_title"] = "Registration Error."
					context["msg_body"] = "\(err)"
				} else {
					context["msg_title"] = "You are registered."
					context["msg_body"] = "Check your email for an email from us. It contains instructions to complete your signup!"
				}
			} else {

			}
			response.render(template: "views/msg", context: context)
		}
	}

	
}
