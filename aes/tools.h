#include <stdio.h>
#include <stdlib.h>

#ifndef AES_TOOLS_H
#define AES_TOOLS_H

typedef unsigned char byte;

void print_hex(unsigned char* buffer, int buffer_length);
byte* hexstr_to_hex(const char* buffer);

#endif