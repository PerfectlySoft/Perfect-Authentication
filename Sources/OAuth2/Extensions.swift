//
//  Extensions.swift
//  Perfect Authentication / OAuth2
//
//  Created by Jonathan Guthrie on 2016-10-24.
//
//

import SwiftString
import PerfectLib

func urlencode(dict: [String: String]) -> String {

	let httpBody = dict.map { (key, value) in
		return key + "=" + value
		}
		.joined(separator: "&")
//		.data(using: .utf8)

	return httpBody

}

/// A lightweight HTTP Response Header Parser
/// transform the header into a dictionary with http status code
class HTTPHeaderParser {

	private var _dic: [String:String] = [:]
	private var _version: String? = nil
	private var _code : Int = -1
	private var _status: String? = nil

	/// HTTPHeaderParser default constructor
	/// - header: the HTTP response header string
	public init(header: String) {

		// parse the header into lines,
		_ = header.components(separatedBy: .newlines)
			// remove all null lines
			.filter{!$0.isEmpty}
			// map each line into the dictionary
			.map{

				// most HTTP header lines have a patter of "variable name: value"
				let range = $0.range(of: ":")

				if (range == nil && $0.hasPrefix("HTTP/")) {
					// except the first line, typically "HTTP/1.0 200 OK", so split it first
					let http = $0.tokenize()

					// parse the tokens
					_version = http[0].trimmed()
					_code = http[1].toInt()!
					_status = http[2].trimmed()
				} else {

					// split the line into a dictionary item expression
					//	let key = $0.left(range)
					//	let val = $0.right(range).trimmed()
					let key = $0.substring(to: (range?.upperBound)!)
					let val = $0.substring(from: (range?.lowerBound)!).trimmed()

					// insert or update the dictionary with this item
					_dic.updateValue(val, forKey: key)
				}
		}
	}

	/// HTTP response header information by keywords
	public var variables: [String:String] {
		get { return _dic }
	}

	/// The HTTP response code, e.g.,, HTTP/1.1 200 OK -> let code = 200
	public var code: Int {
		get { return _code }
	}

	/// The HTTP response code, e.g.,, HTTP/1.1 200 OK -> let status = "OK"
	public var status: String {
		get { return _status ?? "" }
	}

	/// The HTTP response code, e.g.,, HTTP/1.1 200 OK -> let version = "HTTP/1.1"
	public var version: String {
		get { return _version ?? "" }
	}
}
