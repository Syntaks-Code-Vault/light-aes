#include "ecb.h"

#ifndef AES_H
#define AES_H

#define MODE_ECB    1
#define MODE_CBC    2
#define MODE_CTR    3
#define MODE_OFB    4
#define MODE_CFB    5

typedef struct _aes {
    aes_ecb instance;
    byte mode;
    byte* iv_buffer;
} aes;

aes create_aes_instance(byte* key, byte key_length, byte mode);

#endif