//
//  main.swift
//  Perfect Authentication Testing
//
//  Created by Jonathan Guthrie on 207-01-18.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//
import PerfectLib
import PerfectHTTP
import PerfectHTTPServer
import PerfectSession

config()

SessionConfig.name = "TestingAuthentication"
SessionConfig.idle = 3600

// Optional
SessionConfig.cookieDomain = "localhost"
SessionConfig.IPAddressLock = false
SessionConfig.userAgentLock = false
SessionConfig.CSRF.checkState = false
SessionConfig.CORS.enabled = false

let port1 = 8181

let confData = [
	"servers": [
		[
			"name":"localhost",
			"port":port1,
			"routes":[
				["method":"get", "uri":"/", "handler":Handlers.main],

				["method":"get", "uri":"/to/facebook", "handler":Handlers.sendToFacebook],

				["method":"get", "uri":"/auth/response", "handler":Handlers.authResponse],
				["method":"get", "uri":"/**", "handler":PerfectHTTPServer.HTTPHandler.staticFiles,
				 "documentRoot":"./webroot",
				 "allowResponseFilters":true]
			],
			"filters":[
				[
					"type":"response",
					"priority":"high",
					"name":PerfectHTTPServer.HTTPFilter.contentCompression,
					],
				[
					"type":"request",
					"priority":"high",
					"name":SessionMemoryFilter.filterAPIRequest,
					],
				[
					"type":"response",
					"priority":"high",
					"name":SessionMemoryFilter.filterAPIResponse,
					]
			]
		]
	]
]

do {
	// Launch the servers based on the configuration data.
	try HTTPServer.launch(configurationData: confData)
} catch {
	fatalError("\(error)") // fatal error launching one of the servers
}
