#ifndef _AES_T_TABLE_
#define _AES_T_TABLE_

#include <stdint.h>

#include "aes_sbox.h"
#include "aes_tbox.h"


/*
Te0[x] = S [x].[02, 01, 01, 03];
Te1[x] = S [x].[03, 02, 01, 01];
Te2[x] = S [x].[01, 03, 02, 01];
Te3[x] = S [x].[01, 01, 03, 02];
Te4[x] = S [x].[01, 01, 01, 01];

Td0[x] = Si[x].[0e, 09, 0d, 0b];
Td1[x] = Si[x].[0b, 0e, 09, 0d];
Td2[x] = Si[x].[0d, 0b, 0e, 09];
Td3[x] = Si[x].[09, 0d, 0b, 0e];
Td4[x] = Si[x].[01, 01, 01, 01];
*/

const uint rcon_r[] = {
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};



void aes_encrypt_v1(const uchar* plain, uchar* cipher, const uchar* key);
void aes_decrypt_v1(const uchar* cipher, uchar* plain, const uchar* key);
void aes_decrypt_v1_reverse(const uchar* cipher, uchar* plain, const uchar* key);

#endif