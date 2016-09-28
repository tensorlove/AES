#include "aux.h"
#include <stdio.h>
#include <cstring>

void print_hex(const uchar* p, int n) {
    for (int i=0; i<n; i++)
        printf("%02x ", p[i]);
}

bool starts_with(const char* text, const char* pattern) {
	if (strlen(pattern) > strlen(text))
		return false;
	return memcmp(text, pattern, strlen(pattern)) == 0;
}
