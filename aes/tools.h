#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef AES_TOOLS_H
#define AES_TOOLS_H

typedef unsigned char byte;

void __xor16(byte* dst, byte* src);
void __copy16(byte* dst, byte* src);
void __inc16(byte* dst);

void print_hex(byte* buffer, int buffer_length);
byte* hexstr_to_hex(const char* buffer);

void generate_random_bytes(byte* buffer, byte buffer_length);

#endif