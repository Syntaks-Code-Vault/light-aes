#include <stdio.h>
#include "aes/tools.h"
#include "aes/core.h"

void main() {
    FILE* test_data = fopen("test_data.bin", "wb");

    byte status_byte;
    byte* key_buffer;
    byte* pt_buffer;
    byte* ct_buffer;

    byte mode, key_size, data_size;

    // NIST FIPS PUB 197
    mode = MODE_ECB;
    key_buffer = hexstr_to_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    data_size = AES_BLOCK_SIZE;
    pt_buffer = hexstr_to_hex("00112233445566778899aabbccddeeff");

    key_size = KEY_SIZE_128;
    status_byte = 0b00000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
    fwrite(ct_buffer, 1, data_size, test_data);

    key_size = KEY_SIZE_192;
    status_byte = 0b00000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("dda97ca4864cdfe06eaf70a0ec0d7191");
    fwrite(ct_buffer, 1, data_size, test_data);

    key_size = KEY_SIZE_256;
    status_byte = 0b00000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("8ea2b7ca516745bfeafc49904b496089");
    fwrite(ct_buffer, 1, data_size, test_data);

    // NISP SP 800-38A
    data_size = 4 * AES_BLOCK_SIZE;
    pt_buffer = hexstr_to_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

    mode = MODE_ECB; key_size = KEY_SIZE_128;
    status_byte = 0b10000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    key_buffer = hexstr_to_hex("2b7e151628aed2a6abf7158809cf4f3c");
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
    fwrite(ct_buffer, 1, data_size, test_data);

    mode = MODE_ECB; key_size = KEY_SIZE_192;
    status_byte = 0b10000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    key_buffer = hexstr_to_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");
    fwrite(ct_buffer, 1, data_size, test_data);

    mode = MODE_ECB; key_size = KEY_SIZE_256;
    status_byte = 0b10000000 | (mode << 4) | (key_size >> 2);
    fwrite(&status_byte, 1, 1, test_data);
    key_buffer = hexstr_to_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    fwrite(key_buffer, 1, key_size, test_data);
    fwrite(pt_buffer, 1, data_size, test_data);
    ct_buffer = hexstr_to_hex("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7");
    fwrite(ct_buffer, 1, data_size, test_data);

    fclose(test_data);
}