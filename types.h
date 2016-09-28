#ifndef __TYPE_DEF__
#define __TYPE_DEF__

#include <stdint.h>

#define uint    uint32_t
#define uchar   uint8_t

#define u32 	uint32_t
#define u8 		uint8_t

#define SWAP32(x) (((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24)&0xff000000))

#endif