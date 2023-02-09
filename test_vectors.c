#include <stdio.h>
#include "aes/core.h" 

int main() {
    byte* key_buffer;
    byte* iv_buffer;
    byte* pt_buffer;
    byte* ct_buffer;
    byte* buffer;

    byte data_length;
    byte tP = 0;
    byte tF = 0;

    // NIST FIPS PUB 197
    printf("\n\nNIST FIPS 197 Test Vector Equivalence (Single Block Tests)\n");
    printf("==========================================================================================\n");

    data_length = AES_BLOCK_SIZE;
    key_buffer = hexstr_to_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    pt_buffer = hexstr_to_hex("00112233445566778899aabbccddeeff");
    buffer = (byte*) malloc(data_length);

    for (byte key_length = KEY_SIZE_128 ; key_length <= KEY_SIZE_256 ; key_length += 8) {
        switch (key_length) {
            case KEY_SIZE_128: ct_buffer = hexstr_to_hex("69c4e0d86a7b0430d8cdb78070b4c55a"); break;
            case KEY_SIZE_192: ct_buffer = hexstr_to_hex("dda97ca4864cdfe06eaf70a0ec0d7191"); break;
            case KEY_SIZE_256: ct_buffer = hexstr_to_hex("8ea2b7ca516745bfeafc49904b496089"); break;
        };

        printf("\nTest Vectors for ECB-AES-%d\n", key_length * 8); 
        printf("--------------------------------------------------------------------------------\n");
        printf("Key        : "); print_hex(key_buffer, key_length);
        printf("Plaintext  : "); print_hex(pt_buffer, AES_BLOCK_SIZE);

        __copy(buffer, pt_buffer, data_length);
        
        aes_ecb* instance = create_aes_ecb_instance(key_buffer, key_length);
        encrypt_ecb(instance, buffer);

        printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
        printf("Expected   : "); print_hex(ct_buffer, AES_BLOCK_SIZE);
        byte P = __eq(ct_buffer, buffer, data_length);

        decrypt_ecb(instance, buffer);
        printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
        P *= __eq(pt_buffer, buffer, data_length);

        tP += P;
        tF += !P;

        printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");
    }

    // NISP SP 800-38A
    printf("\n\nNIST SP 800-38A Test Vector Equivalence (Four Block Tests)\n");
    printf("==========================================================================================\n");

    data_length = 4 * AES_BLOCK_SIZE;
    pt_buffer = hexstr_to_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

    for (byte key_length = KEY_SIZE_128 ; key_length <= KEY_SIZE_256 ; key_length += 8) {
        switch (key_length) {
            case KEY_SIZE_128: key_buffer = hexstr_to_hex("2b7e151628aed2a6abf7158809cf4f3c"); break;
            case KEY_SIZE_192: key_buffer = hexstr_to_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"); break;
            case KEY_SIZE_256: key_buffer = hexstr_to_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"); break;
        };

        for (byte mode = MODE_ECB ; mode <= MODE_OFB ; mode++) {
            switch (mode) {
                case MODE_ECB: 
                    printf("\nTest Vectors for ECB-AES-%d\n", key_length * 8); 
                    switch (key_length) {
                        case KEY_SIZE_128: ct_buffer = hexstr_to_hex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"); break;
                        case KEY_SIZE_192: ct_buffer = hexstr_to_hex("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"); break;
                        case KEY_SIZE_256: ct_buffer = hexstr_to_hex("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"); break;
                    };
                    break;
                case MODE_CTR:
                    printf("\nTest Vectors for CTR-AES-%d\n", key_length * 8); 
                    switch (key_length) {
                        case KEY_SIZE_128: ct_buffer = hexstr_to_hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"); break;
                        case KEY_SIZE_192: ct_buffer = hexstr_to_hex("1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"); break;
                        case KEY_SIZE_256: ct_buffer = hexstr_to_hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"); break;
                    };
                    break;
                case MODE_CBC:
                    printf("\nTest Vectors for CBC-AES-%d\n", key_length * 8);
                    switch (key_length) {
                        case KEY_SIZE_128: ct_buffer = hexstr_to_hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"); break;
                        case KEY_SIZE_192: ct_buffer = hexstr_to_hex("4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"); break;
                        case KEY_SIZE_256: ct_buffer = hexstr_to_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"); break;
                    };
                    break;
                case MODE_CFB:
                    printf("\nTest Vectors for CFB-AES-%d\n", key_length * 8);
                    switch (key_length) {
                        case KEY_SIZE_128: ct_buffer = hexstr_to_hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"); break;
                        case KEY_SIZE_192: ct_buffer = hexstr_to_hex("cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff"); break;
                        case KEY_SIZE_256: ct_buffer = hexstr_to_hex("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471"); break;
                    };
                    break;
                case MODE_OFB:
                    printf("\nTest Vectors for OFB-AES-%d\n", key_length * 8);
                    switch (key_length) {
                        case KEY_SIZE_128: ct_buffer = hexstr_to_hex("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"); break;
                        case KEY_SIZE_192: ct_buffer = hexstr_to_hex("cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a"); break;
                        case KEY_SIZE_256: ct_buffer = hexstr_to_hex("dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484"); break;
                    };
                    break;
            };
            iv_buffer = hexstr_to_hex((mode == MODE_CTR) ? "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" : "000102030405060708090a0b0c0d0e0f");


            printf("--------------------------------------------------------------------------------\n");
            printf("Key        : "); print_hex(key_buffer, key_length);
            if (mode != MODE_ECB) {
                printf("IV / Nonce : "); print_hex(iv_buffer, AES_BLOCK_SIZE);
            }
            printf("Plaintext  : "); print_hex(pt_buffer, AES_BLOCK_SIZE); 
            printf("             "); print_hex(pt_buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(pt_buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(pt_buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

            __copy(buffer, pt_buffer, data_length);

            aes* instance = create_aes_instance(key_buffer, key_length, mode);
            if (mode != MODE_ECB)
                __copy(instance -> iv_buffer, iv_buffer, AES_BLOCK_SIZE);
            encrypt_aes(instance, buffer, data_length);

            printf("\nCiphertext : "); print_hex(buffer, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("Expected   : "); print_hex(ct_buffer, AES_BLOCK_SIZE);
            printf("             "); print_hex(ct_buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(ct_buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(ct_buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            byte P = __eq(buffer, ct_buffer, data_length);

            instance = create_aes_instance(key_buffer, key_length, mode);
            if (mode != MODE_ECB)
                __copy(instance -> iv_buffer, iv_buffer, AES_BLOCK_SIZE);
            decrypt_aes(instance, buffer, data_length);

            printf("\nDecrypted  : "); print_hex(buffer, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            printf("             "); print_hex(buffer + 3 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            P *= __eq(pt_buffer, buffer, data_length);

            tP += P;
            tF += !P;

            printf("------------------------------------------------------------------------%s----\n", P ? "PASS" : "FAIL");
        }
    }

    printf("\n\nTest Summary\n");
    printf("==========================================================================================\n");
    printf("Total Pass : %d\n", tP); 
    printf("Total Fail : %d\n", tF); 
    printf("==================================================================================%s====\n", tF ? "FAIL" : "PASS");

    return 0;
}