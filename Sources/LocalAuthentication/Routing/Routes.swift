//
//  WebHandlers.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-02-06.
//
//

import PerfectHTTPServer

func mainAuthenticationRoutes() -> [[String: Any]] {

	var routes: [[String: Any]] = [[String: Any]]()

	// WEB
	routes.append(["method":"get", "uri":"/", "handler":WebHandlers.main])
	routes.append(["method":"post", "uri":"/login", "handler":WebHandlers.login])
	routes.append(["method":"get", "uri":"/logout", "handler":WebHandlers.logout])

	routes.append(["method":"get", "uri":"/register", "handler":WebHandlers.register])
	routes.append(["method":"post", "uri":"/register", "handler":WebHandlers.registerPost])
	routes.append(["method":"get", "uri":"/verifyAccount/{passvalidation}", "handler":WebHandlers.registerVerify])
	routes.append(["method":"post", "uri":"/registrationCompletion", "handler":WebHandlers.registerCompletion])

	// JSON
	routes.append(["method":"get", "uri":"/api/v1/session", "handler":JSONHandlers.session])
	routes.append(["method":"get", "uri":"/api/v1/logout", "handler":JSONHandlers.logout])
	routes.append(["method":"post", "uri":"/api/v1/register", "handler":JSONHandlers.register])
	routes.append(["method":"login", "uri":"/api/v1/login", "handler":JSONHandlers.login])



	routes.append(["method":"get", "uri":"/**", "handler":PerfectHTTPServer.HTTPHandler.staticFiles,
	               "documentRoot":"./webroot",
	               "allowResponseFilters":true])

	return routes
}
