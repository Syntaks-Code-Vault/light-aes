#include "core.h"

aes* create_aes_instance(byte* key, byte key_length, byte mode) {
    aes* instance = (aes*) malloc(sizeof(aes));

    if (key_length == KEY_SIZE_128 || key_length == KEY_SIZE_192 || key_length == KEY_SIZE_256) {
        aes_ecb* ecb_instance = create_aes_ecb_instance(key, key_length);

        instance -> instance = ecb_instance;
        instance -> mode = mode;

        if (mode == MODE_ECB)
            instance -> iv_buffer = NULL;
        else {
            // instance -> iv_buffer = (byte*) malloc(16);
            // generate_random_bytes(instance -> iv_buffer, 16);
            instance -> iv_buffer = hexstr_to_hex("000102030405060708090a0b0c0d0e0f");
        }
    }

    return instance;
}

void encrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length) {
    byte* internal_state = (byte*) malloc(16);

    if (!(instance -> mode & 0xF0))
        instance -> mode = 0xA0 | (instance -> mode & 0x0F);

    for (unsigned int i = 0 ; i < buffer_length; i += 16) {
        switch (instance -> mode & 0x0F) {
            case MODE_ECB:
                encrypt_ecb(instance -> instance, buffer + i);
                break;

            case MODE_CTR:
                if ((instance -> mode & 0xF0) == 0xA0) {
                    __copy16(internal_state, instance -> iv_buffer);
                    __inc16(instance -> iv_buffer);
                    encrypt_ecb(instance -> instance, internal_state);
                    __xor16(buffer + i, internal_state);
                }
                break;

            case MODE_CBC:
                if ((instance -> mode & 0xF0) == 0xA0) {
                    __xor16(buffer + i, instance -> iv_buffer);
                    encrypt_ecb(instance -> instance, buffer + i);
                    __copy16(instance -> iv_buffer, buffer + i);
                }
                break;
        }
    }
}

void decrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length) {
    byte* internal_state = (byte*) malloc(16);

    if (!(instance -> mode & 0x80))
        instance -> mode = 0xC0 | (instance -> mode & 0x0F);

    for (unsigned int i = 0 ; i < buffer_length; i += 16) {
        switch (instance -> mode & 0x0F) {
            case MODE_ECB:
                decrypt_ecb(instance -> instance, buffer + i);
                break;

            case MODE_CTR:
                if ((instance -> mode & 0xF0) == 0xC0) {
                    __copy16(internal_state, instance -> iv_buffer);
                    __inc16(instance -> iv_buffer);
                    encrypt_ecb(instance -> instance, internal_state);
                    __xor16(buffer + i, internal_state);
                }
                break;

            case MODE_CBC:
                if ((instance -> mode & 0xF0) == 0xC0) {
                    __copy16(internal_state, buffer + i);
                    decrypt_ecb(instance -> instance, buffer + i);
                    __xor16(buffer + i, instance -> iv_buffer);
                    __copy16(instance -> iv_buffer, internal_state);
                }
                break;
        }
    }
}