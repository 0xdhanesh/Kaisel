// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KaiselKit",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "KaiselKit", targets: ["KaiselKit"]),
    ],
    targets: [
        .target(
            name: "CIntegrityCore",
            path: "Sources/CIntegrityCore",
            publicHeadersPath: "include",
            cSettings: [
                .define("RASP_CORE", to: "1"),
            ]
        ),
        .target(
            name: "KaiselKit",
            dependencies: ["CIntegrityCore"],
            path: "Sources/KaiselKit",
            resources: [.copy("Resources/PrivacyInfo.xcprivacy")],
            linkerSettings: [
                .linkedFramework("DeviceCheck"),
                .linkedFramework("CryptoKit"),
                .linkedFramework("Security"),
                .linkedFramework("UIKit"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        .testTarget(
            name: "KaiselKitTests",
            dependencies: ["KaiselKit"],
            path: "Tests/KaiselKitTests"
        ),
    ]
)
