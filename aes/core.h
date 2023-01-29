#include "ecb.h"
#include "tools.h"

#ifndef AES_H
#define AES_H

#define MODE_ECB    1
#define MODE_CTR    2
#define MODE_CBC    3
#define MODE_CFB    4
#define MODE_OFB    5

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