//
//  Secp256k1.swift
//  secp256-swift
//
//  Created by Ho Hien on 2/25/21.
//  Copyright © 2020 Bitmark Inc. All rights reserved.
//

import Foundation
import secp256k1_c

public enum Secp256k1 {
}

extension Secp256k1 {
    
    public enum Signing {
    
        public struct PublicKey {
            
            private let baseKey: Secp256k1.Signing.PublicKeyImplementation

            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.baseKey = try Secp256k1.Signing.PublicKeyImplementation(rawRepresentation: data)
            }

            fileprivate init(baseKey: Secp256k1.Signing.PublicKeyImplementation) {
                self.baseKey = baseKey
            }

            public var rawRepresentation: Data {
                self.baseKey.rawRepresentation
            }
        }
        
        public struct PrivateKey {
            
            private let baseKey: Secp256k1.Signing.PrivateKeyImplementation

            public init() {
                self.baseKey = Secp256k1.Signing.PrivateKeyImplementation()
            }

            public var publicKey: PublicKey {
                PublicKey(baseKey: self.baseKey.publicKey)
            }

            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.baseKey = try Secp256k1.Signing.PrivateKeyImplementation(rawRepresentation: data)
            }

            public var rawRepresentation: Data {
                self.baseKey.rawRepresentation
            }
        }
    }
}

extension Secp256k1.Signing {

    @usableFromInline struct PrivateKeyImplementation {

        private let privateKeyBytes: SecureBytes

        private let publicKeyBytes: [UInt8]
        
        @usableFromInline var publicKey: Secp256k1.Signing.PublicKeyImplementation {
            return PublicKeyImplementation(self.publicKeyBytes)
        }

        @usableFromInline init() {
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }

            // Setup private and public key variables
            var pubkeyLen = 33
            var cPubkey = secp256k1_pubkey()
            var pubkey = [UInt8](repeating: 0, count: 33)
            let privatekey = SecureBytes(count: 128)
            let privkey = Data(privatekey).withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })

            // Verify the context and keys are setup correctly
            guard secp256k1_context_randomize(context, privkey) == 1,
                secp256k1_ec_pubkey_create(context, &cPubkey, privkey) == 1,
                secp256k1_ec_pubkey_serialize(context, &pubkey, &pubkeyLen, &cPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 1 else {
                self.privateKeyBytes = privatekey
                self.publicKeyBytes = pubkey
                return
            }

            // Save
            self.privateKeyBytes = privatekey
            self.publicKeyBytes = pubkey
        }

        init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }

            // Setup private and public key variables
            var pubkeyLen = 33
            var cPubkey = secp256k1_pubkey()
            var pubkey = [UInt8](repeating: 0, count: 33)
            let privatekey = SecureBytes(bytes: data)
            let privkey = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })

            // Verify the context and keys are setup correctly
            guard secp256k1_context_randomize(context, privkey) == 1,
                  secp256k1_ec_pubkey_create(context, &cPubkey, privkey) == 1,
                  secp256k1_ec_pubkey_serialize(context, &pubkey, &pubkeyLen, &cPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 1 else {
                self.privateKeyBytes = privatekey
                self.publicKeyBytes = pubkey
                return
            }

            // Save
            self.privateKeyBytes = privatekey
            self.publicKeyBytes = pubkey            
        }

        @usableFromInline var rawRepresentation: Data {
            Data(self.privateKeyBytes)
        }
        
    }

    @usableFromInline struct PublicKeyImplementation {

        private let keyBytes: [UInt8]

        @usableFromInline init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            self.keyBytes = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
        }

        init(_ keyBytes: [UInt8]) {
            self.keyBytes = keyBytes
        }

        @usableFromInline var rawRepresentation: Data {
            Data(self.keyBytes)
        }
        
    }
}
