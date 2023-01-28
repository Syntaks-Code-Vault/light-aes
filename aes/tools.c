#include "tools.h"

byte rand_seeded = 0;

void __xor16(byte* dst, byte* src) {
    for (byte i = 0 ; i < 16 ; i++)
        dst[i] ^= src[i];
}

void __copy16(byte* dst, byte* src) {
    for (byte i = 0 ; i < 16 ; i++)
        dst[i] = src[i];
}

void __inc16(byte* dst) {
    for (byte i = 15 ; i >= 0 ; i--) {
        dst[i]++;
        if (dst[i] != 0)
            break;
    }
}

void print_hex(byte* buffer, int buffer_length) {
    printf("0x");
    for (int i = 0 ; i < buffer_length ; i++)
        printf("%02x", buffer[i]);
    printf("\n");
}

byte xtoi(char c) {
    if (c >= 48 && c < 58)
        return (c - 48);
    else if (c >= 65 && c < 71)
        return (c - 55);
    else if (c >= 97 && c < 103)
        return (c - 87);
}

byte* hexstr_to_hex(const char* buffer) {
    int byte_len = 0;
    while (buffer[byte_len++]);

    byte_len = (byte_len + 1) / 2;
    byte* hex = (byte*) malloc(byte_len);

    for (int i = 0 ; i < byte_len ; i++) {
        byte b = xtoi(buffer[2 * i]) << 4;
        b |= buffer[2 * i + 1] ? xtoi(buffer[2 * i + 1]) : 0;

        hex[i] = b;
    }

    return hex;
}

void generate_random_bytes(byte* buffer, byte buffer_length) {
    if (!rand_seeded)
        srand((unsigned int)(buffer + time(NULL) + buffer_length + ++rand_seeded));

    for (byte i = 0 ; i < buffer_length ; i += 2) {
        unsigned int r = rand();

        buffer[i] = r & 0x00FF;
        if ((i + 1) < buffer_length)
            buffer[i + 1] = r >> 8;
    }
}