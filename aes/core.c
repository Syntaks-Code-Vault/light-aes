#include "core.h"

aes create_aes_instance(byte* key, byte key_length, byte mode) {
    aes instance;

    if (key_length == KEY_SIZE_128 || key_length == KEY_SIZE_192 || key_length == KEY_SIZE_256) {
        aes_ecb ecb_instance;

        ecb_instance.key_length = key_length;
        do {
            ecb_instance.key[key_length] = key[key_length];
        } while (key_length-- > 0);

        // MODE CHECKS
    }

    return instance;
}