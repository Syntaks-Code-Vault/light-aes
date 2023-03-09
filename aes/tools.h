#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#ifndef AES_TOOLS_H
#define AES_TOOLS_H

typedef uint8_t byte;

void __xor(byte* dst, byte* src, byte n);
void __copy(byte* dst, byte* src, byte n);
void __inc(byte* dst, byte n);
byte __eq(byte* a, byte* b, byte n);

void print_hex(byte* buffer, int buffer_length);
byte* hexstr_to_hex(const char* buffer);

void generate_random_bytes(byte* buffer, byte buffer_length);

#endif