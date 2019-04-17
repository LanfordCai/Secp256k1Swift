# Secp256k1Swift

A secondary encapsulation of https://github.com/Boilertalk/secp256k1.swift, well-tested and easy to use.

## Integration

You can use [The Swift Package Manager](https://swift.org/package-manager) to install `Secp256k1Swift` by adding the proper description to your `Package.swift` file:

```swift
import PackageDescription

let package = Package(
    name: "YOUR_PROJECT_NAME",
    dependencies: [
        .package(url: "https://github.com/LanfordCai/Secp256k1Swift.git", from: "0.1.2"),
    ]
)
```
Then run `swift build` whenever you get prepared.

## Basic Usage

#### Generate Secp256k1 key pairs

```swift
let (privkey, pubkey) = try! Secp256k1.keyPair()
```

#### Verify a private key

```swift
let result = Secp256k1.isValidPrivateKey(privkey)
```

#### Sign a message

```swift
let sig = try! Secp256k1.sign(msg: msg, with: privkey, nonceFunction: .default)
```

#### Verify a signature

```swift
let result = Secp256k1.verify(msg: msg, sig: sig, pubkey: pubkey)
```

#### Sign compact

```swift
let (sig, recID) = try! Secp256k1.signCompact(msg: msg, with: privkey, nonceFunction: .default)
```

#### Verify compact

```swift
let result = Secp256k1.verifyCompact(msg: msg, sig: sig, pubkey: pubkey)
```

For more usage examples, please checkout the Tests

## Test Vectors

The test vectors are from https://github.com/btccom/secp256k1-go
