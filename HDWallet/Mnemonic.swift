//
//  Mnemonic.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/04.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation
import HDWallet.Private
import secp256k1

public struct Mnemonic {
    // It's called entropy(熵) in 3rd party framework
    public enum Strength : Int {
        case `default` = 128
        case low = 160
        case medium = 192
        case high = 224
        case veryHigh = 256
    }

    public enum Language {
        case english
        case japanese
        case korean
        case spanish
        case simplifiedChinese
        case traditionalChinese
        case french
        case italian
    }

    // MARK: - Mnemonics generate
    public static func generate(strength: Strength = .default, language: Language = .english) throws -> [String] {
        let byteCount = strength.rawValue / 8
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, byteCount, $0) }
        guard status == errSecSuccess else { throw MnemonicError.randomBytesError }
        return generate(entropy: bytes, language: language)
    }

    // MARK: - Mnemonics generate with custom entropy
    static func generate(entropy : Data, language: Language = .english) -> [String] {
        let list = wordList(for: language)
        var bin = String(entropy.flatMap { ("00000000" + String($0, radix:2)).suffix(8) })

        let hash = Crypto.sha256(entropy)
        let bits = entropy.count * 8
        let cs = bits / 32

        let hashbits = String(hash.flatMap { ("00000000" + String($0, radix:2)).suffix(8) })
        let checksum = String(hashbits.prefix(cs))
        bin += checksum

        var mnemonic = [String]()
        for i in 0..<(bin.count / 11) {
            let wi = Int(bin[bin.index(bin.startIndex, offsetBy: i * 11)..<bin.index(bin.startIndex, offsetBy: (i + 1) * 11)], radix: 2)!
            mnemonic.append(String(list[wi]))
        }
        return mnemonic
    }

    // MARK: - Seed generate
    public static func seed(mnemonic m: [String], passphrase: String = "") -> Data {
        let mnemonic = m.joined(separator: " ").decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let seed = _Key.deriveKey(mnemonic, salt: salt, iterations: 2048, keyLength: 64)
        return seed
    }
}

// MARK: - Helper
extension Mnemonic {
    // Requirements:
    // 1. Minimum 12 words
    // 2. Words.count % 3 == 0
    // 3. Every word must be in dictionary (https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md)
    // 4. Words must be in valid order
    // 5. Checksum bits should match (should never throw on that)
    public static func isValid(_ string: String, language: Language = .english) throws -> Bool {

        let wordList = string.components(separatedBy: " ")

        // Check wordlist satisfy the required count
        guard wordList.count >= 12 else {
            throw EntropyError.notEnoughtWords
        }
        guard wordList.count % 3 == 0 else {
            throw EntropyError.invalidNumberOfWords
        }

        // Check the mnemonic word is found in thesaurus
        var bitString = ""
        let list = Mnemonic.wordList(for: language).map(String.init)
        for word in wordList {
            guard let idx = list.index(of: word) else {
                throw EntropyError.wordNotFound(word)
            }

            let idxAsInt = list.startIndex.distance(to: idx)
            let stringForm = String(UInt16(idxAsInt), radix: 2).leftPadding(toLength: 11, withPad: "0")
            bitString.append(stringForm)
        }

        // Check the words order
        let stringCount = bitString.count
        guard stringCount % 33 == 0 else {
            throw EntropyError.invalidOrderOfWords
        }

        // Check the CheckSum
        // The purpose of a checksum is to check the sum. It's a way to let you know if you got the right sequence of numbers.
        // Example: 63841 (6+3+8+4 = 21)
        // Write down 4 numbers, and use an extra 5th digit as a checksum where the 5th number is calculated by summing the first 4 number and taking the last digit of the result.
        // if I mistype one digit: 63941, the checksum would be invalid (6+3+9+4 = 22) and the mistake would be detected before
        let position = (bitString.count - bitString.count / 33)

        let entropyBits = bitString[0..<position]
        let entropy = entropyBits.interpretAsBinaryData()


        let checksumBits = bitString[position..<bitString.count]
        let checksum = String(Crypto.sha256(entropy).bitsInRange(0, checksumBits.count), radix: 2).leftPadding(toLength: checksumBits.count, withPad: "0")

        guard checksum == checksumBits else {
            throw EntropyError.checksumFailed(checksum, checksumBits)
        }

        return true
    }

    private static func wordList(for language: Language) -> [String.SubSequence] {
        switch language {
        case .english:
            return WordList.english
        case .japanese:
            return WordList.japanese
        case .korean:
            return WordList.korean
        case .spanish:
            return WordList.spanish
        case .simplifiedChinese:
            return WordList.simplifiedChinese
        case .traditionalChinese:
            return WordList.traditionalChinese
        case .french:
            return WordList.french
        case .italian:
            return WordList.italian
        }
    }
}

public enum EntropyError: Swift.Error {
    case notEnoughtWords
    case invalidNumberOfWords
    case wordNotFound(String)
    case invalidOrderOfWords
    case checksumFailed(String, String)

    public var localizedDescription: String {
        switch self {
        case .notEnoughtWords:
            return ""
        case .invalidNumberOfWords:
            return ""
        case .wordNotFound:
            return ""
        case .invalidOrderOfWords:
            return ""
        case .checksumFailed:
            return ""
        }
    }
}

public enum MnemonicError : Error {
    case randomBytesError
}

extension Data {
    func bitsInRange(_ startingBit: Int, _ length: Int) -> UInt64 { // return max of 8 bytes for simplicity, non-public
        //        if startingBit + length / 8 > count, length > 64, startingBit > 0, length >= 1 { return nil }
        let bytes = self[(startingBit / 8) ..< (startingBit + length + 7) / 8]
        let padding = Data(repeating: 0, count: 8 - bytes.count)
        let padded = bytes + padding
        var uintRepresentation = UInt64(bigEndian: padded.withUnsafeBytes { $0.pointee })
        uintRepresentation = uintRepresentation << (startingBit % 8)
        uintRepresentation = uintRepresentation >> UInt64(64 - length)
        return uintRepresentation
    }
}


extension Array {
    /// Splits array by chunks
    /// - parameter chunkSize: size of each subarray
    public func split(intoChunksOf chunkSize: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: chunkSize).map {
            let endIndex = ($0.advanced(by: chunkSize) > self.count) ? self.count - $0 : chunkSize
            return Array(self[$0 ..< $0.advanced(by: endIndex)])
        }
    }
}

extension String {
    subscript (bounds: CountableClosedRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start...end])
    }

    subscript (bounds: CountableRange<Int>) -> String {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return String(self[start..<end])
    }
}

extension String {
    func split(intoChunksOf chunkSize: Int) -> [String] {
        var output = [String]()
        let splittedString = map { $0 }
            .split(intoChunksOf: chunkSize)
        splittedString.forEach {
            output.append($0.map { String($0) }.joined(separator: ""))
        }
        return output
    }

    func interpretAsBinaryData() -> Data {
        let padded = padding(toLength: ((count + 7) / 8) * 8, withPad: "0", startingAt: 0)
        let byteArray = padded.split(intoChunksOf: 8).map { UInt8(strtoul($0, nil, 2)) }
        return Data(byteArray)
    }
    func leftPadding(toLength: Int, withPad character: Character) -> String {
        let stringLength = count
        if stringLength < toLength {
            return String(repeatElement(character, count: toLength - stringLength)) + self
        } else {
            return String(suffix(toLength))
        }
    }
}
