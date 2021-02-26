//
//  Secp256k1Error.swift
//  secp256-swift
//
//  Created by Ho Hien on 2/26/21.
//  Copyright © 2020 Bitmark Inc. All rights reserved.
//

import Foundation

public enum Secp256k1Error: Error {
    case signingError
    case other(reason: String)

    var localizedDescription: String {
        switch self {
        case .signingError:
            return "singing error"
        case .other(let reason):
            return reason
        }
    }
}
