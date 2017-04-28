//
//  WebHandlers.registerCompletion.swift
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

	// registerCompletion
	static func registerCompletion(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let t = request.session?.data["csrf"] as? String ?? ""
			if let i = request.session?.userid, !i.isEmpty { response.redirect(path: "/") }
			var context: [String : Any] = ["title": "Perfect Authentication Server"]

			if let v = request.param(name: "passvalidation"), !(v as String).isEmpty {

				let acc = Account(validation: v)

				if acc.id.isEmpty {
					context["msg_title"] = "Account Validation Error."
					context["msg_body"] = ""
					response.render(template: "views/msg", context: context)
					return
				} else {

					if let p1 = request.param(name: "p1"), !(p1 as String).isEmpty,
						let p2 = request.param(name: "p2"), !(p2 as String).isEmpty,
						p1 == p2 {

						if let digestBytes = p1.digest(.sha256),
							let hexBytes = digestBytes.encode(.hex),
							let hexBytesStr = String(validatingUTF8: hexBytes) {
							print(hexBytesStr)
							acc.password = hexBytesStr

							//							let digestBytes2 = p1.digest(.sha256)
							//							let hexBytes2 = digestBytes2?.encode(.hex)
							//							let hexBytesStr2 = String(validatingUTF8: hexBytes2!)
							//							print(hexBytesStr2)
						}
						//						acc.password = BCrypt.hash(password: p1)
						acc.usertype = .standard
						do {
							try acc.save()
							request.session?.userid = acc.id
							context["msg_title"] = "Account Validated and Completed."
							context["msg_body"] = "<p><a class=\"button\" href=\"/\">Click to continue</a></p>"
							response.render(template: "views/msg", context: context)

						} catch {
							print(error)
						}
					} else {
						context["msg_body"] = "<p>Account Validation Error: The passwords must not be empty, and must match.</p>"
						context["passvalidation"] = v
						context["csrfToken"] = t
						response.render(template: "views/registerComplete", context: context)
						return
					}

				}
			} else {
				context["msg_title"] = "Account Validation Error."
				context["msg_body"] = "Code not found."
				response.render(template: "views/msg", context: context)
			}
		}
	}
}
