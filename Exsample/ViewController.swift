//
//  ViewController.swift
//  Exsample
//
//  Created by Liu Pengpeng on 2018/8/30.
//  Copyright © 2018年 ONEROOT PROJECT. All rights reserved.
//

import UIKit
import HDWallet

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        let xPrivKey = HDPrivateKey(seed: Mnemonic.seed(mnemonic: "hair park remain verb raven cement deliver neglect easy opinion custom gauge dress holiday diary".components(separatedBy: " ")), network: .mainnet)
        print(xPrivKey.extended())
        
        let keychain = HDKeychain(seed: Mnemonic.seed(mnemonic: "say tongue select oil blossom pond parent orphan crater sadness position coin".components(separatedBy: " ")))
        
        let prvkey = try! keychain.derivedKey(path: "m/1'/0").getPrivateKey()
        print(prvkey.description)
        print(prvkey.publicKey().description)
        
        let hash = Crypto.sha256sha256("get|/wallets|{}".data(using: .utf8)!)
        print(try! Crypto.sign(hash, privateKey: prvkey).hexEncodedString());
        // 30440220332ec58cf6eda347dc7ea65ad9794ae67557cf51171561946a0a37b7da27966202207b46989b343b5f7fd0c3120ffb1bafe85f9e446793273015461a66d2db924a16 ✅
        // 304502210086b53780831d477b1f42d51a0f0601d31f672421710cd47c9ed5939c994b414302202c0a296c4be7c9632a544f6f4f2b0b50c0c80116391ba9ff2857ec6805cbe33a ❌
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

extension Data {
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        for i in 0..<len {
            let j = hex.index(hex.startIndex, offsetBy: i * 2)
            let k = hex.index(j, offsetBy: 2)
            let bytes = hex[j..<k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
    
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}
