//
//  File.swift
//  secp256-swift
//
//  Created by Ho Hien on 2/25/21.
//  Copyright © 2020 Bitmark Inc. All rights reserved.
//

import Foundation

extension Data {
    var bytes: [UInt8] {
        var b: [UInt8] = []
        b.append(contentsOf: self)
        return b
    }
    
    var hexString: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
    
    init?(hexString: String) {
        let length = hexString.count / 2
        var data = Data(capacity: length)
        for i in 0 ..< length {
            let j = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j..<k]
            if var byte = UInt8(bytes, radix: 16) {
                data.append(&byte, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
}
