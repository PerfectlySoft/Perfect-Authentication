//
//  InitializeSchema.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-02-06.
//
//
import PerfectLib
import StORM
import PostgresStORM
import JSONConfig
import PerfectSessionPostgreSQL

func initializeSchema() -> [String:Any] {
	var opts = [String:Any]()
	if let config = JSONConfig(name: "./config/ApplicationConfiguration.json") {
		let dict = config.getValues()!
		opts["httpPort"] = dict["httpport"] as! Int
		// StORM Connector Config
		PostgresConnector.host        = dict["postgreshost"] as? String ?? ""
		PostgresConnector.username    = dict["postgresuser"] as? String ?? ""
		PostgresConnector.password    = dict["postgrespwd"] as? String ?? ""
		PostgresConnector.database    = dict["postgresdbname"] as? String ?? ""
		PostgresConnector.port        = dict["postgresport"] as? Int ?? 0

		// Outbound email config
		SMTPConfig.mailserver         = dict["mailserver"] as? String ?? ""
		SMTPConfig.mailuser			  = dict["mailuser"] as? String ?? ""
		SMTPConfig.mailpass			  = dict["mailpass"] as? String ?? ""
		SMTPConfig.mailfromaddress    = dict["mailfromaddress"] as? String ?? ""
		SMTPConfig.mailfromname        = dict["mailfromname"] as? String ?? ""

		opts["baseURL"] = dict["baseURL"] as? String ?? ""
		AuthenticationVariables.baseURL = dict["baseURL"] as? String ?? ""

		// session driver config
		PostgresSessionConnector.host = PostgresConnector.host
		PostgresSessionConnector.port = PostgresConnector.port
		PostgresSessionConnector.username = PostgresConnector.username
		PostgresSessionConnector.password = PostgresConnector.password
		PostgresSessionConnector.database = PostgresConnector.database
		PostgresSessionConnector.table = "sessions"

	} else {
		print("Unable to get Configuration")

		PostgresConnector.host        = "localhost"
		PostgresConnector.username    = "perfect"
		PostgresConnector.password    = "perfect"
		PostgresConnector.database    = "perfect_testing"
		PostgresConnector.port        = 5432
		
	}

//	StORMdebug = true

	// Account
	let a = Account()
	try? a.setup()

	// Application
	let app = Application()
	try? app.setup()

	// Access Token
	let at = AccessToken()
	try? at.setup()


	return opts
}
