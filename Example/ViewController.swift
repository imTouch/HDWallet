//
//  ViewController.swift
//  Example
//
//  Created by Linsz on 2018/11/22.
//  Copyright © 2018 ONEROOT PROJECT. All rights reserved.
//

import UIKit
import HDWallet

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        let wordlist = "pretty roast city lesson turtle favorite lesson canvas surface dismiss addict piece"

        do {
            let valid = try Mnemonic.isValid(wordlist)
            if valid {
                print("Valid mnemonics")
            }
        } catch {
            print("Invalid mnemonics")
        }
    }
}

