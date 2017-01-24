//
//  Config.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-23.
//
//

import PerfectLib
import JSONConfig
import AuthProviders


struct AppCredentials {
	var clientid = ""
	var clientsecret = ""
}

func config() {
	if let configData = JSONConfig(name: "./config/ApplicationConfiguration.json") {
		if let dict = configData.getValues() {
			if let fb = dict["facebookAppID"] { FacebookConfig.appid = fb as! String }
			if let fb = dict["facebookSecret"] { FacebookConfig.secret = fb as! String }
			if let fb = dict["edpointAfterAuth"] { FacebookConfig.edpointAfterAuth = fb as! String }
			if let fb = dict["redirectAfterAuth"] { FacebookConfig.redirectAfterAuth = fb as! String }
		}
	} else {
		print("Unable to get Configuration")
	}

}
