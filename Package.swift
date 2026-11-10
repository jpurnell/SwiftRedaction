// swift-tools-version: 6.2
// legibility:description: One catalogue of named, tested rules that remove secret-shaped and personal-looking text from strings, with two shipped policies and a test-support product that proves a secret reached no output.

import PackageDescription

let package = Package(
    name: "SwiftRedaction",
    // The floors of the sibling packages. The core is Foundation-only, so it is intended to build on Linux as well;
    // that is UNVERIFIED (no Linux host yet, see the README).
    platforms: [.macOS(.v14), .iOS(.v17), .watchOS(.v10), .tvOS(.v17), .visionOS(.v1)],
    products: [
        .library(name: "Redaction", targets: ["Redaction"]),
        // For TEST targets only: it imports Testing. An app must never link it.
        .library(name: "RedactionTestSupport", targets: ["RedactionTestSupport"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "Redaction",
            resources: [.copy("Redaction.docc")],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .target(
            name: "RedactionTestSupport",
            dependencies: ["Redaction"],
            resources: [.copy("RedactionTestSupport.docc")],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .testTarget(
            name: "RedactionTests",
            dependencies: ["Redaction", "RedactionTestSupport"],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .testTarget(
            name: "RedactionTestSupportTests",
            dependencies: ["RedactionTestSupport", "Redaction"],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
    ]
)
