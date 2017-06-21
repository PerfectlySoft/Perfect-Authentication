import PackageDescription

let package = Package(
    name: "Perfect-Authentication",
    targets: [
		Target(name: "OAuth2"),
		Target(
			name: "LocalAuthentication",
			dependencies: []
		)
		],
    dependencies: [
		.Package(url: "https://github.com/PerfectlySoft/PerfectLib.git", majorVersion: 2),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", majorVersion: 2),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-Logger.git", majorVersion: 1),
		.Package(url: "https://github.com/iamjono/SwiftString.git", majorVersion: 2),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-Session.git", majorVersion: 1),

		.Package(url: "https://github.com/iamjono/JSONConfig.git", majorVersion: 1),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-RequestLogger.git", majorVersion: 1),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-SMTP", majorVersion: 1),
		.Package(url: "https://github.com/SwiftORM/Postgres-StORM.git", majorVersion: 1),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-Session-PostgreSQL.git", majorVersion: 1),
		.Package(url: "https://github.com/PerfectlySoft/Perfect-Mustache.git", majorVersion: 2),
		]

)
