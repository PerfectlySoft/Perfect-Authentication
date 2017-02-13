//
//  Common.swift
//  Perfect-Authentication
//
//  Created by Jonathan Guthrie on 2017-01-24.
//
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import PerfectHTTP
import PerfectSession

extension HTTPResponse {
	/// Provides a convenience method for redirects
	public func redirect(path: String, sessionid: String = "") {
		if !sessionid.isEmpty  {
			self.setHeader(.custom(name: "Authorization"), value: "Bearer \(sessionid)")
		}
		self.status = .found
		self.setHeader(.location, value: path)
		self.completed()
	}
}

// Could be improved, I'm sure...
func digIntoDictionary(mineFor: [String], data: [String: Any]) -> Any {
	if mineFor.count == 0 { return "" }
	for (key,value) in data {
		if key == mineFor[0] {
			var newMine = mineFor
			newMine.removeFirst()
			if newMine.count == 0 {
				return value
			} else if value is [String: Any] {
				return digIntoDictionary(mineFor: newMine, data: value as! [String : Any])
			}
		}
	}
	return ""
}
