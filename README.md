[![Test Vector Equivalence](https://github.com/Syntaks-Code-Vault/light-aes/actions/workflows/cmake_build_and_run.yml/badge.svg)](https://github.com/Syntaks-Code-Vault/light-aes/actions/workflows/cmake_build_and_run.yml)

# light-aes
A Memory Optimized AES-128/192/256 Implementation in C

Supports the following [Block Cipher Modes of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation):
- ECB (Electronic Code Book)
- CTR (Counter)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feed Back)
- OFB (Output Feed Back)

Validated over the Standard Test Vectors provided in:
- [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
