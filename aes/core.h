#include "ecb.h"
#include "tools.h"

#ifndef AES_H
#define AES_H

#define MODE_ECB    0
#define MODE_CTR    1
#define MODE_CBC    2
#define MODE_CFB    3
#define MODE_OFB    4

typedef struct _aes {
    aes_ecb* instance;
    byte mode;
    byte* iv_buffer;
} aes;

aes* create_aes_instance(byte* key, byte key_length, byte mode);

void encrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length);
void decrypt_aes(aes* instance, byte* buffer, unsigned int buffer_length);

void destroy_aes_instance(aes* instance);

#endif