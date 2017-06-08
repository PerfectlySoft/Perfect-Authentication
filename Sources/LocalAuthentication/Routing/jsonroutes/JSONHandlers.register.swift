//
//  JSONHandlers.register.swift
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
	
	// POST request for register form
	public static func register(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			if let i = request.session?.userid, !i.isEmpty {
				_ = try? response.setBody(json: ["msg":"Already logged in"])
				response.completed()
				return
			}


			if let postBody = request.postBodyString, !postBody.isEmpty {
				do {
					let postBodyJSON = try postBody.jsonDecode() as? [String: String] ?? [String: String]()
					if let u = postBodyJSON["username"], !u.isEmpty,
						let e = postBodyJSON["email"], !e.isEmpty {
						let err = Account.register(u, e, .provisional, baseURL: AuthenticationVariables.baseURL)
						if err != .noError {
							Handlers.error(request, response, error: "Registration Error: \(err)", code: .badRequest)
							return
						} else {
							_ = try response.setBody(json: ["error":"Registration Success", "msg":"Check your email for an email from us. It contains instructions to complete your signup!"])
							response.completed()
							return
						}
					} else {
						Handlers.error(request, response, error: "Please supply a username and password", code: .badRequest)
						return
					}
				} catch {
					Handlers.error(request, response, error: "Invalid JSON", code: .badRequest)
					return
				}
			} else {
				Handlers.error(request, response, error: "Registration Error: Insufficient Data", code: .badRequest)
				return
			}

		}
	}

}
