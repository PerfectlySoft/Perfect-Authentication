//
//  JSONHandlers.login.swift
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
	
	// POST request for login form
	static func login(data: [String:Any]) throws -> RequestHandler {
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
						let p = postBodyJSON["password"], !p.isEmpty {

						do{
							let acc = try Account.login(u, p)
							request.session?.userid = acc.id
							_ = try response.setBody(json: ["error":"Login Success"])
							response.completed()
							return
						} catch {
							Handlers.error(request, response, error: "Login Failure", code: .badRequest)
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
				Handlers.error(request, response, error: "Login Error: Insufficient Data", code: .badRequest)
				return
			}
		}
	}
	

}
