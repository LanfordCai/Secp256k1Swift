@testable import Secp256k1Swift
import XCTest
import Yaml

final class Secp256k1SwiftTests: XCTestCase {
    func testKeyPair() {
        for _ in 1 ... 100 {
            let (privkey, pubkey) = try! Secp256k1.keyPair()
            XCTAssertEqual(privkey.count, 32)
            let ePubkey = try! Secp256k1.derivePublicKey(for: privkey, with: .uncompressed)
            XCTAssertEqual(ePubkey, pubkey)
        }
    }

    func testIsValidPrivateKey() {
        for _ in 1 ... 100 {
            let (privkey, pubkey) = try! Secp256k1.keyPair()
            XCTAssertTrue(Secp256k1.isValidPrivateKey(privkey))
            XCTAssertFalse(Secp256k1.isValidPrivateKey(pubkey))
        }
    }

    func testIsValidPublicKey() {
        let pubkeyVectors = loadTestVectors(vectorsName: "pubkey_vectors")
        for vector in pubkeyVectors {
            let (privkey, cpubkey, pubkey) = (
                [UInt8](hex: vector["seckey"]!),
                [UInt8](hex: vector["compressed"]!),
                [UInt8](hex: vector["pubkey"]!)
            )

            XCTAssertTrue(Secp256k1.isValidPublicKey(cpubkey))
            XCTAssertTrue(Secp256k1.isValidPublicKey(pubkey))
            XCTAssertFalse(Secp256k1.isValidPublicKey(privkey))
        }
    }

    func testCompression() {
        for _ in 1 ... 100 {
            let (privkey, pubkey) = try! Secp256k1.keyPair()
            XCTAssertEqual(try! Secp256k1.compression(of: pubkey), Secp256k1.Compression.uncompressed)

            let cPubkey = try! Secp256k1.compressPublicKey(pubkey)
            XCTAssertEqual(try! Secp256k1.compression(of: cPubkey), Secp256k1.Compression.compressed)

            XCTAssertThrowsError(try Secp256k1.compression(of: privkey))
        }
    }

    func testVerify() {
        let signVectors = loadTestVectors(vectorsName: "sign_vectors")
        for vector in signVectors {
            let (msg, privkey, sig) = (
                [UInt8](hex: vector["msg"]!),
                [UInt8](hex: vector["privkey"]!),
                [UInt8](hex: String(vector["sig"]!.dropLast(2)))
            )

            let pubkey = try! Secp256k1.derivePublicKey(for: privkey)
            var result = Secp256k1.verify(msg: msg, sig: sig, pubkey: pubkey)
            XCTAssertTrue(result)

            let invalidSig = sig + [1]
            result = Secp256k1.verify(msg: msg, sig: invalidSig, pubkey: pubkey)
            XCTAssertFalse(result)
        }
    }

    func testSign() {
        let signVectors = loadTestVectors(vectorsName: "sign_vectors")
        for vector in signVectors {
            let (msg, privkey, eSig) = (
                [UInt8](hex: vector["msg"]!),
                [UInt8](hex: vector["privkey"]!),
                [UInt8](hex: String(vector["sig"]!.dropLast(2)))
            )

            let sig = try! Secp256k1.sign(msg: msg, with: privkey, nonceFunction: .default)
            XCTAssertEqual(eSig, sig)
        }
    }

    func testDerivePubkey() {
        let pubkeyVectors = loadTestVectors(vectorsName: "pubkey_vectors")
        for vector in pubkeyVectors {
            let (privkey, cpubkey, pubkey) = (
                [UInt8](hex: vector["seckey"]!),
                [UInt8](hex: vector["compressed"]!),
                [UInt8](hex: vector["pubkey"]!)
            )

            let uncompressedPubkey = try! Secp256k1.derivePublicKey(for: privkey, with: .uncompressed)
            XCTAssertEqual(uncompressedPubkey, pubkey)
            let compressedPubkey = try! Secp256k1.derivePublicKey(for: privkey, with: .compressed)
            XCTAssertEqual(compressedPubkey, cpubkey)
        }
    }

    func testCompressPubkeyAndDecompressPubkey() {
        let pubkeyVectors = loadTestVectors(vectorsName: "pubkey_vectors")
        for vector in pubkeyVectors {
            let (cpubkey, pubkey) = (
                [UInt8](hex: vector["compressed"]!),
                [UInt8](hex: vector["pubkey"]!)
            )
            XCTAssertEqual(try! Secp256k1.compressPublicKey(pubkey), cpubkey)
            XCTAssertEqual(try! Secp256k1.decompressPublicKey(cpubkey), pubkey)
        }
    }

    func testPubkeyTweakAdd() {
        let pubkeyTweakAddVectors = loadTestVectors(vectorsName: "pubkey_tweak_add_vectors")
        for vector in pubkeyTweakAddVectors {
            let (pubkey, tweak, tweaked) = (
                [UInt8](hex: vector["publicKey"]!),
                [UInt8](hex: vector["tweak"]!),
                [UInt8](hex: vector["tweaked"]!)
            )

            XCTAssertEqual(try! Secp256k1.publicKeyTweakAdd(pubkey, tweak: tweak), tweaked)

            let cpubkey = try! Secp256k1.compressPublicKey(pubkey)
            let ctweaked = try! Secp256k1.publicKeyTweakAdd(cpubkey, tweak: tweak)
            XCTAssertEqual(try! Secp256k1.decompressPublicKey(ctweaked), tweaked)
        }
    }

    func testPubkeyTweakMul() {
        let pubkeyTweakMulVectors = loadTestVectors(vectorsName: "pubkey_tweak_mul_vectors")
        for vector in pubkeyTweakMulVectors {
            let (pubkey, tweak, tweaked) = (
                [UInt8](hex: vector["publicKey"]!),
                [UInt8](hex: vector["tweak"]!),
                [UInt8](hex: vector["tweaked"]!)
            )

            XCTAssertEqual(try! Secp256k1.publicKeyTweakMul(pubkey, tweak: tweak), tweaked)

            let cpubkey = try! Secp256k1.compressPublicKey(pubkey)
            let ctweaked = try! Secp256k1.publicKeyTweakMul(cpubkey, tweak: tweak)
            XCTAssertEqual(try! Secp256k1.decompressPublicKey(ctweaked), tweaked)
        }
    }

    func testPrivkeyTweakAdd() {
        let privkeyTweakAddVectors = loadTestVectors(vectorsName: "privkey_tweak_add_vectors")
        for vector in privkeyTweakAddVectors {
            let (privkey, tweak, tweaked) = (
                [UInt8](hex: vector["privkey"]!),
                [UInt8](hex: vector["tweak"]!),
                [UInt8](hex: vector["tweaked"]!)
            )

            XCTAssertEqual(try! Secp256k1.privateKeyTweakAdd(privkey, tweak: tweak), tweaked)
        }
    }

    func testPrivkeyTweakMul() {
        let privkeyTweakMulVectors = loadTestVectors(vectorsName: "privkey_tweak_mul_vectors")
        for vector in privkeyTweakMulVectors {
            let (privkey, tweak, tweaked) = (
                [UInt8](hex: vector["privkey"]!),
                [UInt8](hex: vector["tweak"]!),
                [UInt8](hex: vector["tweaked"]!)
            )

            XCTAssertEqual(try! Secp256k1.privateKeyTweakMul(privkey, tweak: tweak), tweaked)
        }
    }

    func testSignCompactAndVerifyCompactAndRecoverCompact() {
        for _ in 1 ... 100 {
            let (privkey, pubkey) = try! Secp256k1.keyPair()
            let (msg, _) = try! Secp256k1.keyPair()

            let (sig, recID) = try! Secp256k1.signCompact(msg: msg, with: privkey, nonceFunction: .default)

            XCTAssertTrue(Secp256k1.verifyCompact(msg: msg, sig: sig, pubkey: pubkey))

            let recPubkey = try! Secp256k1.recoverCompact(msg: msg, sig: sig, recID: recID, compression: .uncompressed)
            XCTAssertEqual(recPubkey, pubkey)

            let cPubkey = try! Secp256k1.compressPublicKey(pubkey)
            let reccPubkey = try! Secp256k1.recoverCompact(msg: msg, sig: sig, recID: recID, compression: .compressed)
            XCTAssertEqual(reccPubkey, cPubkey)
        }
    }

    static var allTests = [
        ("testKeyPair", testKeyPair),
        ("testIsValidPublicKey", testIsValidPublicKey),
        ("testIsValidPrivateKey", testIsValidPrivateKey),
        ("testCompression", testCompression),
        ("testVerify", testVerify),
        ("testSign", testSign),
        ("testDerivePubkey", testDerivePubkey),
        ("testCompressPubkeyAndDecompressPubkey", testCompressPubkeyAndDecompressPubkey),
        ("testPubkeyTweakAdd", testPubkeyTweakAdd),
        ("testPubkeyTweakMul", testPubkeyTweakMul),
        ("testPrivkeyTweakAdd", testPrivkeyTweakAdd),
        ("testPrivkeyTweakMul", testPrivkeyTweakMul),
        ("testSignCompactAndVerifyCompactAndRecoverCompact", testSignCompactAndVerifyCompactAndRecoverCompact),
    ]

    private func loadTestVectors(vectorsName: String) -> [[String: String]] {
        let path = testVectorPath(withFilename: vectorsName)
        print(path)
        guard let content = try? String(contentsOfFile: path),
            let testVectors = try? Yaml.load(content).array else {
            XCTFail("Can't load test vector file")
            return []
        }

        return testVectors.map { (yamlVector: Yaml) -> [String: String] in
            yamlVector.dictionary!.reduce([:]) { (currentDict, kv) -> [String: String] in
                let (yamlKey, yamlValue) = kv
                var dict = currentDict
                dict[yamlKey.string!] = yamlValue.string!
                return dict
            }
        }
    }

    private func testVectorPath(withFilename name: String) -> String {
        guard let path = Bundle(for: Secp256k1SwiftTests.self).path(forResource: name, ofType: "yaml") else {
            return "./Tests/Resources/\(name).yaml"
        }
        return path
    }
}
