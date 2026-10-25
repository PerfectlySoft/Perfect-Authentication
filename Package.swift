// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PerfectAuthentication",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "PerfectOAuth2", targets: ["PerfectOAuth2"]),
    ],
    dependencies: [
        // SHA-256 for PKCE (RFC 7636 S256) and HMAC-SHA256 for Facebook's appsecret_proof.
        // The range overlaps Perfect-SMTP (4.0.0..<5.0.0) and Perfect-NIO (3.0.0..<5.0.0).
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "PerfectOAuth2",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "Sources/PerfectOAuth2",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectOAuth2Tests",
            dependencies: ["PerfectOAuth2"],
            path: "Tests/PerfectOAuth2Tests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
