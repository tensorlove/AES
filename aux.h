#ifndef __AUX_H__
#define __AUX_H__

#include <stdint.h>

#define uchar	uint8_t

void print_hex(const uchar*, int);
bool starts_with(const char* text, const char* pattern);


#endif