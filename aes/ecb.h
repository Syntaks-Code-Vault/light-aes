#include <stdlib.h>

#ifndef AES_ECB_H
#define AES_ECB_H

#define KEY_SIZE_128    16
#define KEY_SIZE_192    24
#define KEY_SIZE_256    32

#define AES_BLOCK_SIZE  16

typedef unsigned char byte;

typedef struct _aes_ecb {
    byte key_length;
    byte* key;
} aes_ecb;

aes_ecb* create_aes_ecb_instance(byte* key, byte key_length);

void encrypt_ecb(aes_ecb* instance, byte* buffer);
void decrypt_ecb(aes_ecb* instance, byte* buffer);

void destroy_aes_ecb_instance(aes_ecb* instance);

#endif