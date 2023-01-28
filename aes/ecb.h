#include <stdlib.h>

#ifndef AES_ECB_H
#define AES_ECB_H

#define KEY_SIZE_128    16
#define KEY_SIZE_192    24
#define KEY_SIZE_256    32

typedef unsigned char byte;

typedef struct _aes_ecb {
    byte key_length;
    byte* key;
} aes_ecb;

aes_ecb* create_aes_ecb_instance(const byte* key, byte key_length);

void encrypt_ecb(aes_ecb* instance, byte* buffer);
void decrypt_ecb(aes_ecb* instance, byte* buffer);

#endif