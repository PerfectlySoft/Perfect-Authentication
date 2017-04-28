//
//  SMTP.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-02-07.
//
//

import PerfectSMTP

public struct SMTPConfig {
	public static var mailserver = ""
	public static var mailuser = ""
	public static var mailpass = ""

	public static var mailfromname = ""
	public static var mailfromaddress = ""
}

public class Utility {

	public static func sendMail(name: String = "", address: String, subject: String, html: String = "", text: String = "") {

		if html.isEmpty && text.isEmpty { return }

		let client = SMTPClient(url: SMTPConfig.mailserver, username: SMTPConfig.mailuser, password: SMTPConfig.mailpass)

		var email = EMail(client: client)
		email.subject = subject

		// set the sender info
		email.from = Recipient(name: SMTPConfig.mailfromname, address: SMTPConfig.mailfromaddress)
		if !html.isEmpty { email.content = html }
		if !text.isEmpty { email.text = text }
		email.to.append(Recipient(name: name, address: address))

		do {
			try email.send { code, header, body in
				/// response info from mail server
//				print("code: \(code)")
//				print("header: \(header)")
//				print("body: \(body)")
			}
		} catch {
			print("email.send error: \(error)")
			/// something wrong
		}
	}
}
