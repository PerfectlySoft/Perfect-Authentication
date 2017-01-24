//
//  Handlers.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-23.
//
//

import PerfectHTTP
import AuthProviders
import TurnstileCrypto
import OAuth2

class Handlers {

	static func main(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let context: [String : Any] = [
				"sessionID": request.session?.token ?? "",
				"userID": request.session?.userid ?? "",
				"loginType": request.session?.data["loginType"] ?? "",
				"accessToken": request.session?.data["accessToken"] ?? "",
				"firstName": request.session?.data["firstName"] ?? "",
				"lastName": request.session?.data["lastName"] ?? "",
				"picture": request.session?.data["picture"] ?? ""
			]
			response.render(template: "templates/index", context: context)
		}
	}

	static func authResponse(data: [String:Any]) throws -> RequestHandler {
		return {
			request, response in
			let fb = Facebook(clientID: FacebookConfig.appid, clientSecret: FacebookConfig.secret)
			do {
				guard let state = request.session?.data["state"] else {
					throw OAuth2Error(code: .unsupportedResponseType)
				}
				let t = try fb.exchange(request: request, state: state as! String)
				request.session?.data["accessToken"] = t.accessToken

				let userdata = fb.getUserData(t.accessToken)

				request.session?.data["loginType"] = "facebook"


				if let i = userdata["userid"] {
					request.session?.userid = i as! String
				}
				if let i = userdata["first_name"] {
					request.session?.data["firstName"] = i as! String
				}
				if let i = userdata["last_name"] {
					request.session?.data["lastName"] = i as! String
				}
				if let i = userdata["picture"] {
					request.session?.data["picture"] = i as! String
				}

			} catch {
				print(error)
			}
			response.redirect(path: FacebookConfig.redirectAfterAuth)
		}
	}





	static func sendToFacebook(data: [String:Any]) throws -> RequestHandler {
		let rand = URandom()

		return {
			request, response in
			// Add secure state token to session
			// We expect to get this back from the auth
			request.session?.data["state"] = rand.secureToken
			let fb = Facebook(clientID: FacebookCreds.appid, clientSecret: FacebookCreds.secret)
			response.redirect(path: fb.getLoginLink(state: request.session?.data["state"] as! String))
		}
	}

}
