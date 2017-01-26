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
	public func redirect(path: String) {
		self.status = .found
		self.addHeader(.location, value: path)
		self.completed()
	}
}

