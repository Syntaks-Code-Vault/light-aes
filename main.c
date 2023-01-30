#include <stdio.h>
#include "aes/core.h" 

int main() {
    printf("\n\nNIST FIPS 197 Test Vector Equivalence (Single Block Tests)\n");
    printf("==========================================================================================\n");
   
    byte* buffer = (byte*) malloc(AES_BLOCK_SIZE);
    byte* key = hexstr_to_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte* plaintext = hexstr_to_hex("00112233445566778899aabbccddeeff");

    printf("\nTest Vectors for ECB-AES-128\n");
    printf("--------------------------------------------------------------------------------\n");

    byte P = 1;
    byte* ciphertext = hexstr_to_hex("69c4e0d86a7b0430d8cdb78070b4c55a");

    printf("Key        : "); print_hex(key, KEY_SIZE_128);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, AES_BLOCK_SIZE);
    aes_ecb* instance = create_aes_ecb_instance(key, KEY_SIZE_128);

    encrypt_ecb(instance, buffer);
    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, AES_BLOCK_SIZE);

    decrypt_ecb(instance, buffer);
    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, AES_BLOCK_SIZE);

    free(ciphertext);
    destroy_aes_ecb_instance(instance);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    printf("\nTest Vectors for ECB-AES-192\n");
    printf("--------------------------------------------------------------------------------\n");

    P = 1;
    ciphertext = hexstr_to_hex("dda97ca4864cdfe06eaf70a0ec0d7191");

    printf("Key        : "); print_hex(key, KEY_SIZE_192);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, AES_BLOCK_SIZE);
    instance = create_aes_ecb_instance(key, KEY_SIZE_192);

    encrypt_ecb(instance, buffer);
    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, AES_BLOCK_SIZE);

    decrypt_ecb(instance, buffer);
    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, AES_BLOCK_SIZE);

    free(ciphertext);
    destroy_aes_ecb_instance(instance);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    printf("\nTest Vectors for ECB-AES-256\n");
    printf("--------------------------------------------------------------------------------\n");

    P = 1;
    ciphertext = hexstr_to_hex("8ea2b7ca516745bfeafc49904b496089");

    printf("Key        : "); print_hex(key, KEY_SIZE_256);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, AES_BLOCK_SIZE);
    instance = create_aes_ecb_instance(key, KEY_SIZE_256);

    encrypt_ecb(instance, buffer);
    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, AES_BLOCK_SIZE);

    decrypt_ecb(instance, buffer);
    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, AES_BLOCK_SIZE);

    free(ciphertext);
    destroy_aes_ecb_instance(instance);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    free(buffer);
    free(key);

    printf("\n\nNIST SP 800-38A Test Vector Equivalence (Four Block Tests)\n");
    printf("==========================================================================================\n");

    const byte data_length = 4 * AES_BLOCK_SIZE;
    buffer = (byte*) malloc(data_length);
    plaintext = hexstr_to_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

    printf("\nTest Vectors for ECB-AES-128\n");
    printf("--------------------------------------------------------------------------------\n");

    P = 1;
    key = hexstr_to_hex("2b7e151628aed2a6abf7158809cf4f3c");
    ciphertext = hexstr_to_hex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");

    printf("Key        : "); print_hex(key, KEY_SIZE_128);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE); 
    printf("             "); print_hex(plaintext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, data_length);

    aes* aes_instance = create_aes_instance(key, KEY_SIZE_128, MODE_ECB);
    encrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, data_length);
    
    aes_instance = create_aes_instance(key, KEY_SIZE_128, MODE_ECB);
    decrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, data_length);

    free(key);
    free(ciphertext);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    printf("\nTest Vectors for ECB-AES-192\n");
    printf("--------------------------------------------------------------------------------\n");

    P = 1;
    key = hexstr_to_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    ciphertext = hexstr_to_hex("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");

    printf("Key        : "); print_hex(key, KEY_SIZE_192);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE); 
    printf("             "); print_hex(plaintext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, data_length);

    aes_instance = create_aes_instance(key, KEY_SIZE_192, MODE_ECB);
    encrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, data_length);
    
    aes_instance = create_aes_instance(key, KEY_SIZE_192, MODE_ECB);
    decrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, data_length);

    free(key);
    free(ciphertext);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    printf("\nTest Vectors for ECB-AES-256\n");
    printf("--------------------------------------------------------------------------------\n");

    P = 1;
    key = hexstr_to_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    ciphertext = hexstr_to_hex("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7");

    printf("Key        : "); print_hex(key, KEY_SIZE_256);
    printf("Plaintext  : "); print_hex(plaintext, AES_BLOCK_SIZE); 
    printf("             "); print_hex(plaintext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(plaintext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    __copy(buffer, plaintext, data_length);

    aes_instance = create_aes_instance(key, KEY_SIZE_256, MODE_ECB);
    encrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("Expected   : "); print_hex(ciphertext, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(ciphertext + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(ciphertext, buffer, data_length);
    
    aes_instance = create_aes_instance(key, KEY_SIZE_256, MODE_ECB);
    decrypt_aes(aes_instance, buffer, data_length);
    destroy_aes_instance(aes_instance);

    printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    P *= __eq(plaintext, buffer, data_length);

    free(key);
    free(ciphertext);

    printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");

    return 0;
}