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
            instance -> iv_buffer = (byte*) malloc(AES_BLOCK_SIZE);
            generate_random_bytes(instance -> iv_buffer, AES_BLOCK_SIZE);
        }
    }

    return instance;
}

void destroy_aes_instance(aes* instance) {
    destroy_aes_ecb_instance(instance -> instance);
    if (instance -> iv_buffer != NULL)
        free(instance -> iv_buffer);
    free(instance);
}

void encrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length) {
    byte* internal_state = (byte*) malloc(AES_BLOCK_SIZE);

    if (!(instance -> mode & 0xF0))
        instance -> mode = 0xA0 | (instance -> mode & 0x0F);

    for (unsigned int i = 0 ; i < buffer_length; i += AES_BLOCK_SIZE) {
        switch (instance -> mode & 0x0F) {
            case MODE_ECB:
                encrypt_ecb(instance -> instance, buffer + i);
                break;

            case MODE_CTR:
                if ((instance -> mode & 0xF0) == 0xA0) {
                    __copy(internal_state, instance -> iv_buffer, AES_BLOCK_SIZE);
                    __inc(instance -> iv_buffer, AES_BLOCK_SIZE);
                    encrypt_ecb(instance -> instance, internal_state);
                    __xor(buffer + i, internal_state, AES_BLOCK_SIZE);
                }
                break;

            case MODE_CBC:
                if ((instance -> mode & 0xF0) == 0xA0) {
                    __xor(buffer + i, instance -> iv_buffer, AES_BLOCK_SIZE);
                    encrypt_ecb(instance -> instance, buffer + i);
                    __copy(instance -> iv_buffer, buffer + i, AES_BLOCK_SIZE);
                }
                break;
        }
    }

    free(internal_state);
}

void decrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length) {
    byte* internal_state = (byte*) malloc(AES_BLOCK_SIZE);

    if (!(instance -> mode & 0x80))
        instance -> mode = 0xC0 | (instance -> mode & 0x0F);

    for (unsigned int i = 0 ; i < buffer_length; i += AES_BLOCK_SIZE) {
        switch (instance -> mode & 0x0F) {
            case MODE_ECB:
                decrypt_ecb(instance -> instance, buffer + i);
                break;

            case MODE_CTR:
                if ((instance -> mode & 0xF0) == 0xC0) {
                    __copy(internal_state, instance -> iv_buffer, AES_BLOCK_SIZE);
                    __inc(instance -> iv_buffer, AES_BLOCK_SIZE);
                    encrypt_ecb(instance -> instance, internal_state);
                    __xor(buffer + i, internal_state, AES_BLOCK_SIZE);
                }
                break;

            case MODE_CBC:
                if ((instance -> mode & 0xF0) == 0xC0) {
                    __copy(internal_state, buffer + i, AES_BLOCK_SIZE);
                    decrypt_ecb(instance -> instance, buffer + i);
                    __xor(buffer + i, instance -> iv_buffer, AES_BLOCK_SIZE);
                    __copy(instance -> iv_buffer, internal_state, AES_BLOCK_SIZE);
                }
                break;
        }
    }

    free(internal_state);
}