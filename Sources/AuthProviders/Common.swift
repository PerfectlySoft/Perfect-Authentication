//
//  Common.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-24.
//
//

import PerfectHTTP

extension HTTPResponse {
	public func redirect(path: String) {
		self.status = .found
		self.addHeader(.location, value: path)
		self.completed()
	}
}
