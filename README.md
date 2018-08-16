# HDWallet

Rebuild application program interface based on [BitcoinKit](https://github.com/kishikawakatsumi/BitcoinKit).

## Usage

#### Generate mnemonic

```swift
let mnemonic = try Mnemonic.generate()

let seed = Mnemonic.seed(mnemonic: mnemonic)
```

## Requirements

- iOS 8.0+ / macOS 10.10+ / tvOS 9.0+ / watchOS 2.0+
- Xcode 8.3+
- Swift 3.1+
