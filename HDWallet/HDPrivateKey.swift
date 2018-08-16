//
//  HDPrivateKey.swift
//  HDWallet
//
//  Created by Liu Pengpeng on 2018/6/4.
//

import Foundation
import HDWallet.Private

public class HDPrivateKey {
    public let network: Network
    public let depth: UInt8
    public let fingerprint: UInt32
    public let childIndex: UInt32
    
    let raw: Data
    public let chainCode: Data
    
    public init(serialized: String) {
        let decoded = Base58.decode(serialized)

        // let version = decoded[0..<4]
        // let depth = decoded[4..<5]
        // let fingerPrint = decoded[5..<9]
        // let childIndex = decoded[9..<13]
        // let chainCode = decoded[13..<45]
        // let privateKey = decoded[46..<78]
        // let checksum = decoded[78..<82]
        
        self.network = .mainnet
        
        let privateKey = PrivateKey(data: decoded[46..<78], network: self.network)
        self.raw = privateKey.raw
        
        self.fingerprint = decoded[5..<9].withUnsafeBytes({ $0.pointee })
        self.depth = decoded[4..<5].withUnsafeBytes({ $0.pointee })
        self.chainCode = decoded[13..<45]
        self.childIndex = decoded[9..<13].withUnsafeBytes({ $0.pointee })
    }
    
    public init(privateKey: Data, chainCode: Data, network: Network) {
        self.raw = privateKey
        self.chainCode = chainCode
        self.network = network
        self.depth = 0
        self.fingerprint = 0
        self.childIndex = 0
    }
    
    public convenience init(seed: Data, network: Network) {
        let hmac = Crypto.hmacsha512(data: seed, key: "Bitcoin seed".data(using: .ascii)!)
        let privateKey = hmac[0..<32]
        let chainCode = hmac[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, network: network)
    }
    
    init(privateKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.raw = privateKey
        self.chainCode = chainCode
        self.network = network
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }
    
    public func getHDPublicKey() -> HDPublicKey {
        return HDPublicKey(privateKey: self, chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
    }
    
    public func getPrivateKey() -> PrivateKey {
        return PrivateKey(data: self.raw)
    }
    
    public func extended() -> String {
        var data = Data()
        data += network.xprivkey.bigEndian
        data += depth.littleEndian
        data += fingerprint.littleEndian
        data += childIndex.littleEndian
        data += chainCode
        data += UInt8(0)
        data += raw
        let checksum = Crypto.sha256sha256(data).prefix(4)
        return Base58.encode(data + checksum)
    }
    
    public func derived(at index: UInt32, hardened: Bool = false) throws -> HDPrivateKey {
        // As we use explicit parameter "hardened", do not allow higher bit set.
        if (0x80000000 & index) != 0 {
            fatalError("invalid child index")
        }
        
        guard let derivedKey = _HDKey(privateKey: raw, publicKey: getHDPublicKey().raw, chainCode: chainCode, depth: depth, fingerprint: fingerprint, childIndex: childIndex).derived(at: index, hardened: hardened) else {
            throw DerivationError.derivateionFailed
        }
        return HDPrivateKey(privateKey: derivedKey.privateKey!, chainCode: derivedKey.chainCode, network: network, depth: derivedKey.depth, fingerprint: derivedKey.fingerprint, childIndex: derivedKey.childIndex)
    }
}

public enum DerivationError : Error {
    case derivateionFailed
}
