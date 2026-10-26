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
        // The default transport, NIOTransport: an HTTP/1.1 client with hard size and time bounds on
        // every platform (corelibs URLSession can't be bounded on Linux). Same floors as
        // Perfect-SMTP 6.0.0: nio 2.86.0, nio-ssl 2.31.0 (public `peerCertificate`, read by the
        // DNS-subjectAltName check), swift-asn1 1.2.0 (the subjectAltName parser).
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.86.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.31.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "PerfectOAuth2",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/PerfectOAuth2",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectOAuth2Tests",
            dependencies: [
                "PerfectOAuth2",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ],
            path: "Tests/PerfectOAuth2Tests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
