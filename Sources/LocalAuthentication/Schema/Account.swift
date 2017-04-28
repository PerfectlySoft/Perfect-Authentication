//
//  Account.swift
//  Perfect-OAuth2-Server
//
//  Created by Jonathan Guthrie on 2017-02-06.
//
//

import StORM
import PostgresStORM
import SwiftRandom
import PerfectSMTP

public class Account: PostgresStORM {
	public var id			= ""
	public var username		= ""
	public var password		= ""
	public var email		= ""
	public var usertype: AccountType = .provisional
	public var passvalidation = ""

	let _r = URandom()

	override public func to(_ this: StORMRow) {
		id              = this.data["id"] as? String				?? ""
		username		= this.data["username"] as? String			?? ""
		password        = this.data["password"] as? String			?? ""
		email           = this.data["email"] as? String				?? ""
		usertype        = AccountType.from((this.data["usertype"] as? String)!)
		passvalidation	= this.data["passvalidation"] as? String		?? ""
	}

	func rows() -> [Account] {
		var rows = [Account]()
		for i in 0..<self.results.rows.count {
			let row = Account()
			row.to(self.results.rows[i])
			rows.append(row)
		}
		return rows
	}

	public override init() {
		super.init()
	}

	public init(_ i: String = "", _ u: String, _ p: String = "", _ e: String, _ ut: AccountType = .provisional) {
		super.init()
		id = i
		username = u
		password = p
		email = e
		usertype = ut
		passvalidation = _r.secureToken
	}

	public init(validation: String) {
		super.init()
		try? find(["passvalidation": validation])
	}

	// Register User
	public static func register(_ u: String, _ e: String, _ ut: AccountType = .provisional, baseURL: String) -> OAuth2ServerError {
		let r = URandom()
		let acc = Account(r.secureToken, u, "", e, ut)
		do {
			try acc.create()
		} catch {
			print(error)
			return .registerError
		}

		var h = "<p>Welcome to your new account</p>"
		h += "<p>To get started with your new account, please <a href=\"\(baseURL)/verifyAccount/\(acc.passvalidation)\">click here</a></p>"
		h += "<p>If the link does not work copy and paste the following link into your browser:<br>\(baseURL)/verifyAccount/\(acc.passvalidation)</p>"

		var t = "Welcome to your new account\n"
		t += "To get started with your new account, please click here: \(baseURL)/verifyAccount/\(acc.passvalidation)"


		Utility.sendMail(name: u, address: e, subject: "Welcome to your account", html: h, text: t)

		return .noError
	}
	
	// Register User
	public static func login(_ u: String, _ p: String) throws -> Account {
		if let digestBytes = p.digest(.sha256),
			let hexBytes = digestBytes.encode(.hex),
			let hexBytesStr = String(validatingUTF8: hexBytes) {

			let acc = Account()
			let criteria = ["username":u,"password":hexBytesStr]
			do {
				try acc.find(criteria)
				if acc.usertype == .provisional {
					throw OAuth2ServerError.loginError
				}
				return acc
			} catch {
				print(error)
				throw OAuth2ServerError.loginError
			}
		} else {
			throw OAuth2ServerError.loginError
		}
	}
	


}

public enum AccountType {
	case provisional, standard, admin, inactive

	public static func from(_ str: String) -> AccountType {
		switch str {
		case "admin":
			return .admin
		case "standard":
			return .standard
		case "inactive":
			return .inactive
		default:
			return .provisional
		}
	}
}
