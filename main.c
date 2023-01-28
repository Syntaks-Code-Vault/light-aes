#include <stdio.h>
#include "aes/core.h"

int main() {
    byte* key = hexstr_to_hex("2b7e151628aed2a6abf7158809cf4f3c");
    // byte* key = hexstr_to_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    // byte* key = hexstr_to_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    byte* x = hexstr_to_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

    aes* encrypt_instance = create_aes_instance(key, KEY_SIZE_128, MODE_CBC);

    // __inc16(x);
    // print_hex(x, 16);
    // __inc16(x);
    // print_hex(x, 16);

    // generate_random_bytes(x, 16);
    // print_hex(x, 16);

    // generate_random_bytes(x, 16);
    // print_hex(x, 16);

    encrypt_aes(encrypt_instance, x, 64);
    print_hex(x, 64);

    aes* decrypt_instance = create_aes_instance(key, KEY_SIZE_128, MODE_CBC);

    decrypt_aes(decrypt_instance, x, 64);
    print_hex(x, 64);

    // decrypt_ecb(instance -> instance, x);
    // print_hex(x, 16);

    // byte* x = decrypt_ecb(aes, encrypt_ecb(aes, plaintext));
    

    return 0;
}