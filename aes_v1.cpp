#include "aes_v1.h"
#include <tmmintrin.h>
#include <stdio.h>

const __m128i TRANSPOSE_MASK = _mm_setr_epi8(0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf);
void transpose(__m128i* m) {
    *m = _mm_shuffle_epi8(*m, TRANSPOSE_MASK);
}

void print_state(void* state) {
    uchar* p = (uchar*)state;
    printf("%02x %02x %02x %02x\n", p[0], p[1], p[2], p[3]);
    printf("%02x %02x %02x %02x\n", p[4], p[5], p[6], p[7]);
    printf("%02x %02x %02x %02x\n", p[8], p[9], p[10], p[11]);
    printf("%02x %02x %02x %02x\n", p[12], p[13], p[14], p[15]);
}

const __m128i SHIFTROW_PERMUTATION = _mm_setr_epi8(
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11
);

// SUBBYTE -> SHIFTROW -> MIXCOLUMN
// Hope reduce XOR's from 16 to 3
#define SSM(state_t, sb, buf)   \
    state_t = _mm_setr_epi32(Te0_r[sb[ 0]], Te0_r[sb[ 4]], Te0_r[sb[ 8]], Te0_r[sb[12]]);   \
    buf     = _mm_setr_epi32(Te1_r[sb[ 5]], Te1_r[sb[ 9]], Te1_r[sb[13]], Te1_r[sb[ 1]]);   \
    state_t = _mm_xor_si128(state_t, buf);                                                  \
    buf     = _mm_setr_epi32(Te2_r[sb[10]], Te2_r[sb[14]], Te2_r[sb[ 2]], Te2_r[sb[ 6]]);   \
    state_t = _mm_xor_si128(state_t, buf);                                                  \
    buf     = _mm_setr_epi32(Te3_r[sb[15]], Te3_r[sb[ 3]], Te3_r[sb[ 7]], Te3_r[sb[11]]);   \
    state_t = _mm_xor_si128(state_t, buf);

// Generate ROUND Key
#define GENRKEY(urk, brk, r, temp) \
    temp = urk[3];                              \
    urk[3] = (urk[3] >> 8) | (urk[3] << 24);    \
    brk[12] = sbox[brk[12]];                    \
    brk[13] = sbox[brk[13]];                    \
    brk[14] = sbox[brk[14]];                    \
    brk[15] = sbox[brk[15]];                    \
    urk[3] ^= rcon_r[r];                        \
    urk[0] = urk[0] ^ urk[3];                   \
    urk[1] ^= urk[0];                           \
    urk[2] ^= urk[1];                           \
    urk[3] = urk[2] ^ temp;
    
// Add ROUND Key
#define ADDRKEY(dst, src, rk)  \
    dst = _mm_xor_si128(src, rk)

#define SUBBYTE(sb) 	\
    sb[ 0] = sbox[sb[ 0]];    sb[ 1] = sbox[sb[ 1]];    sb[ 2] = sbox[sb[ 2]];    sb[ 3] = sbox[sb[ 3]];	\
    sb[ 4] = sbox[sb[ 4]];    sb[ 5] = sbox[sb[ 5]];    sb[ 6] = sbox[sb[ 6]];    sb[ 7] = sbox[sb[ 7]];	\
    sb[ 8] = sbox[sb[ 8]];    sb[ 9] = sbox[sb[ 9]];    sb[10] = sbox[sb[10]];    sb[11] = sbox[sb[11]];	\
    sb[12] = sbox[sb[12]];    sb[13] = sbox[sb[13]];    sb[14] = sbox[sb[14]];    sb[15] = sbox[sb[15]];

#define SHIFTROW(dst, src) \
    dst = _mm_shuffle_epi8(src, SHIFTROW_PERMUTATION);


void aes_encrypt_v1(const uchar* plain, uchar* cipher, const uchar* key) {
    __m128i state_s = { 0 };
    __m128i state_t = { 0 };
    __m128i rk = { 0 };

    uint* urk = (uint*)&rk;
    uchar* brk = (uchar*)&rk;

    uchar* sb = (uchar*)&state_s;

    __m128i buf;

    // initial state
    state_s = _mm_loadu_si128((__m128i*)plain);

    // initial round key
    rk = _mm_loadu_si128((__m128i*)key);

    // ROUND 0
    ADDRKEY(state_s, state_s, rk);

    uint temp;
    // ROUND 1 ~ 9
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 0, temp);    ADDRKEY(state_s, state_t, rk);    
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 1, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 2, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 3, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 4, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 5, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 6, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 7, temp);    ADDRKEY(state_s, state_t, rk);
    SSM(state_t, sb, buf);     GENRKEY(urk, brk, 8, temp);    ADDRKEY(state_s, state_t, rk);

    // Final ROUND
    SUBBYTE(sb);
    state_s = _mm_shuffle_epi8(state_s, SHIFTROW_PERMUTATION);
    GENRKEY(urk, brk, 9, temp);
    ADDRKEY(state_s, state_s, rk);

    _mm_storeu_si128((__m128i*)cipher, state_s);
}

const __m128i INVERSE_SHIFTROW_PERMUTATION = _mm_setr_epi8(
     0, 13, 10,  7,
     4,  1, 14, 11,
     8,  5,  2, 15,
    12,  9,  6,  3
);

void aes_decrypt_v1(const uchar* cipher, uchar* plain, const uchar* key) {
}


// From ROUND r key to ROUND r-1 key
#define REVERSE_RKEY_STEP1(uk, r, temp)   \
    uk[3] ^= uk[2];                               \
    uk[2] ^= uk[1];                               \
    uk[1] ^= uk[0];                               \
    temp = (uk[3] >> 8) | (uk[3] << 24);          \
    ((uchar*)&temp)[0] = sbox[((uchar*)&temp)[0]];   \
    ((uchar*)&temp)[1] = sbox[((uchar*)&temp)[1]];    \
    ((uchar*)&temp)[2] = sbox[((uchar*)&temp)[2]];    \
    ((uchar*)&temp)[3] = sbox[((uchar*)&temp)[3]];    \
    temp ^= rcon_r[r];                              \
    uk[0] ^= temp;

#define REVERSE_RKEY_STEP2(k, bk, temp1, temp2)       \
    temp1 = _mm_setr_epi32(Td0_r[sbox[bk[0]]], Td0_r[sbox[bk[4]]], Td0_r[sbox[bk[ 8]]], Td0_r[sbox[bk[12]]]);   \
    temp2 = _mm_setr_epi32(Td1_r[sbox[bk[1]]], Td1_r[sbox[bk[5]]], Td1_r[sbox[bk[ 9]]], Td1_r[sbox[bk[13]]]);   \
    temp1 = _mm_xor_si128(temp2, temp1);                                                                            \
    temp2 = _mm_setr_epi32(Td2_r[sbox[bk[2]]], Td2_r[sbox[bk[6]]], Td2_r[sbox[bk[10]]], Td2_r[sbox[bk[14]]]);   \
    temp1 = _mm_xor_si128(temp2, temp1);                                                                            \
    temp2 = _mm_setr_epi32(Td3_r[sbox[bk[3]]], Td3_r[sbox[bk[7]]], Td3_r[sbox[bk[11]]], Td3_r[sbox[bk[15]]]);   \
    k    = _mm_xor_si128(temp2, temp1);

void aes_decrypt_v1_reverse(const uchar* cipher, uchar* plain, const uchar* key) {
    uint temp;

    __m128i state_s = {};
    __m128i state_t = {};
    __m128i rk = {};
    __m128i rkd = {};

    uint* urk = (uint*)&rk;
    uchar* brk = (uchar*)&rk;

    uchar* brkd = (uchar*)&rkd;

    uchar* sb = (uchar*)&state_s;

    __m128i buf;

    // Generate last round key
    rk = _mm_loadu_si128((__m128i*)key);
    GENRKEY(urk, brk, 0, temp);
    GENRKEY(urk, brk, 1, temp);
    GENRKEY(urk, brk, 2, temp);
    GENRKEY(urk, brk, 3, temp);
    GENRKEY(urk, brk, 4, temp);
    GENRKEY(urk, brk, 5, temp);
    GENRKEY(urk, brk, 6, temp);
    GENRKEY(urk, brk, 7, temp);
    GENRKEY(urk, brk, 8, temp);
	GENRKEY(urk, brk, 9, temp);

    // initial state
    state_s = _mm_loadu_si128((__m128i*)cipher);

#define INVERSE_SUBBYTE(sb) 	\
    sb[ 0] = sbox_i[sb[ 0]];    sb[ 1] = sbox_i[sb[ 1]];    sb[ 2] = sbox_i[sb[ 2]];    sb[ 3] = sbox_i[sb[ 3]];	\
    sb[ 4] = sbox_i[sb[ 4]];    sb[ 5] = sbox_i[sb[ 5]];    sb[ 6] = sbox_i[sb[ 6]];    sb[ 7] = sbox_i[sb[ 7]];	\
    sb[ 8] = sbox_i[sb[ 8]];    sb[ 9] = sbox_i[sb[ 9]];    sb[10] = sbox_i[sb[10]];    sb[11] = sbox_i[sb[11]];	\
    sb[12] = sbox_i[sb[12]];    sb[13] = sbox_i[sb[13]];    sb[14] = sbox_i[sb[14]];    sb[15] = sbox_i[sb[15]];

#define INVERSE_SHIFTROW(dst, src) \
    dst = _mm_shuffle_epi8(src, INVERSE_SHIFTROW_PERMUTATION);

#define SSMR(dst, srcb, buf) \
    dst = _mm_setr_epi32(Td0_r[srcb[ 0]], Td0_r[srcb[ 4]], Td0_r[srcb[ 8]], Td0_r[srcb[12]]);   \
    buf = _mm_setr_epi32(Td1_r[srcb[13]], Td1_r[srcb[ 1]], Td1_r[srcb[ 5]], Td1_r[srcb[ 9]]);   \
    dst = _mm_xor_si128(dst, buf);                                              			    \
    buf = _mm_setr_epi32(Td2_r[srcb[10]], Td2_r[srcb[14]], Td2_r[srcb[ 2]], Td2_r[srcb[ 6]]);   \
    dst = _mm_xor_si128(dst, buf);                                              			    \
    buf = _mm_setr_epi32(Td3_r[srcb[ 7]], Td3_r[srcb[11]], Td3_r[srcb[15]], Td3_r[srcb[ 3]]);   \
    dst = _mm_xor_si128(dst, buf);

    // Final round
    // print_state(&state_s);
    // puts("");
    ADDRKEY(state_s, state_s, rk);

    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 9, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 8, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 7, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 6, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 5, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 4, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 3, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 2, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    SSMR(state_t, sb, buf);     REVERSE_RKEY_STEP1(urk, 1, temp);      rkd = rk;   REVERSE_RKEY_STEP2(rkd, brkd, state_s, buf);      ADDRKEY(state_s, state_t, rkd);
    INVERSE_SHIFTROW(state_s, state_s);                                                       
    INVERSE_SUBBYTE(sb);
    rk = _mm_loadu_si128((__m128i*)key);       ADDRKEY(state_s, state_s, rk);

    _mm_storeu_si128((__m128i*)plain, state_s);
}
