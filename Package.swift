// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Secp256k1Swift",
    products: [
        .library(
            name: "Secp256k1Swift",
            targets: ["Secp256k1Swift"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Boilertalk/secp256k1.swift.git", from: "0.1.0"),
        .package(url: "https://github.com/behrang/YamlSwift.git", from: "3.4.4"),
    ],
    targets: [
        .target(
            name: "Secp256k1Swift",
            dependencies: ["secp256k1"]
        ),
        .testTarget(
            name: "Secp256k1SwiftTests",
            dependencies: ["Secp256k1Swift", "Yaml"]
        ),
    ]
)
