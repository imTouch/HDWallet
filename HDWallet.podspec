Pod::Spec.new do |spec|
  spec.name = 'HDWallet'
  spec.version = '0.1.4'
  spec.summary = 'Hierarchical Deterministic Wallet'
  spec.description = <<-DESC
                       A pure and powerful Swift HDWallet library.
                       ```
                    DESC
  spec.homepage = 'https://github.com/imTouch/HDWallet'
  spec.license = { :type => 'Apache 2.0', :file => 'LICENSE' }
  spec.author = 'Liu Pengpeng'

  spec.requires_arc = true
  spec.source = { git: 'https://github.com/imTouch/HDWallet.git', tag: "v#{spec.version}" }
  spec.source_files = 'HDWallet/**/*.{h,m,swift}', 'Libraries/*'
  spec.private_header_files = 'HDWallet/**/HDWalletInternal.h'
  spec.module_map = 'HDWallet/HDWallet.modulemap'
  spec.ios.deployment_target = '8.0'
  spec.swift_version = '4.1'

  spec.pod_target_xcconfig = { 'SWIFT_WHOLE_MODULE_OPTIMIZATION' => 'YES',
                               'APPLICATION_EXTENSION_API_ONLY' => 'YES',
                               'SWIFT_INCLUDE_PATHS' => '${PODS_ROOT}/HDWallet/Libraries',
                               'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/HDWallet/Libraries/openssl/include" "${PODS_ROOT}/HDWallet/Libraries/secp256k1/include"',
                               'LIBRARY_SEARCH_PATHS' => '"${PODS_ROOT}/HDWallet/Libraries/openssl/lib" "${PODS_ROOT}/HDWallet/Libraries/secp256k1/lib"' }
  # spec.preserve_paths = ['setup', 'Libraries']
  # spec.prepare_command = 'sh setup/build_libraries.sh'
end