// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PerfectAuthentication",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "PerfectOAuth2", targets: ["PerfectOAuth2"]),
    ],
    targets: [
        .target(
            name: "PerfectOAuth2",
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
