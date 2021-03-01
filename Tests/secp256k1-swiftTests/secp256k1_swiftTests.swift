import XCTest
@testable import secp256k1_c
@testable import secp256k1_swift
import CryptoKit

final class secp256k1_swiftTests: XCTestCase {
    
    func testCompressedKeypairCreation() {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

        defer { secp256k1_context_destroy(context) }

        var pubkeyLen = 33
        var cPubkey = secp256k1_pubkey()
        var publicKey = [UInt8](repeating: 0, count: pubkeyLen)
        let privateKey = Data(hexString: "ea73e9add6e35fd7b7dee709771fd34889585bdf35903942135afcddf8e9eb28")!.bytes

        XCTAssertEqual(secp256k1_context_randomize(context, privateKey), 1)
        XCTAssertEqual(secp256k1_ec_pubkey_create(context, &cPubkey, privateKey), 1)
        XCTAssertEqual(secp256k1_ec_pubkey_serialize(context, &publicKey, &pubkeyLen, &cPubkey, UInt32(SECP256K1_EC_COMPRESSED)), 1)

        let expectedPublicKey = Data(hexString: "03be9a2a322e4ffff41eaf147450f343c4c10a70ca30e8d60764d56e6c7a54114e")!.bytes

        XCTAssertEqual(expectedPublicKey, publicKey)
    }
    
    func testCompressedKeypairWithRawData() {
        let expectedPrivateKey = "b53f487ba3c237014e988aee6823ad7efe9502950ee311dd0e2837652fc76535".lowercased()
        let expectedPublicKey = "034ddf6d93434764e7da993eaf49b3240f8c98427d441fa5982d86fb2a1cbcd4b3".lowercased()
        let privateKeyBytes = Data(hexString: expectedPrivateKey)!.bytes
        let privatekey = try! Secp256k1.Signing.PrivateKey(rawRepresentation: privateKeyBytes)

        XCTAssertEqual(expectedPrivateKey, privatekey.rawRepresentation.hexString)
        XCTAssertEqual(expectedPublicKey, privatekey.publicKey.rawRepresentation.hexString)
    }
    
    func testSignatureAndVerifySignature() {
        let privateKeyBytes = Data(hexString: "e6dd32f8761625f105c39a39f19370b3521d845a12456d60ce44debd0a362641")!.bytes
        let privatekey = try! Secp256k1.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
        
        XCTAssertEqual("03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1", privatekey.publicKey.rawRepresentation.hexString)
        
        let message = "Hello world!".data(using: .utf8)!.bytes
        let sig = try! privatekey.signature(for: message)
        
        XCTAssertEqual("3045022100a834a9596c3021524305faa75a83a545780260e059832128d9617f4479876613022036bc08f2aed098d1e598106ab1439d4bcdbed127db73072358a4ca21f3dbd4f2", sig.derRepresentation.hexString)
        XCTAssertTrue(privatekey.publicKey.isValidSignature(sig, for: message))

    }

    static var allTests = [
        ("testCompressedKeypairCreation", testCompressedKeypairCreation),
        ("testCompressedKeypairWithRawData", testCompressedKeypairWithRawData),
        ("testSignatureAndVerifySignature", testSignatureAndVerifySignature)
    ]
}
