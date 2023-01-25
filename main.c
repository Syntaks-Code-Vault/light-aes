#include <stdio.h>
#include "aes/core.h"
#include "aes/ecb.h"
#include "aes/tools.h"

int main() {
    byte* key = hexstr_to_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // byte* key = hexstr_to_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    // byte* key = hexstr_to_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    byte* x = hexstr_to_hex("00112233445566778899aabbccddeeff");

    aes_ecb* aes = create_aes_ecb_instance(key, KEY_SIZE_128);

    printf("Banana!\n");
    print_hex(x, 16);

    encrypt_ecb(aes, x);
    print_hex(x, 16);

    decrypt_ecb(aes, x);
    print_hex(x, 16);

    // byte* x = decrypt_ecb(aes, encrypt_ecb(aes, plaintext));
    

    return 0;
}