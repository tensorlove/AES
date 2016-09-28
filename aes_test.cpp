#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "aux.h"
#include "aes_v1.h"
#include "aes_ref.h"

void usage() {
	printf("aes_test --algorithm={ALG} --repeat={repeat time} [-e|-d]\n");
	printf("\talgorithm : 0 = original, 1 = v1\n");
	printf("\t-e : Encryption\n");
	printf("\t-d : Decryption\n");
}

#define ALG_ORIG	0
#define ALG_V1		1

int main(int argc, char** argv) {
	/*
	printf("const uint Td1_r[] = {\n\t");
	for (int i=0; i<256; i++) {
		printf("0x%08XU, ", SWAP32(Td1[i]));
		if ((i+1)%4==0)
			printf("\n\t");
	}
	printf("};\n\n");

	printf("const uint Td2_r[] = {\n\t");
	for (int i=0; i<256; i++) {
		printf("0x%08XU, ", SWAP32(Td2[i]));
		if ((i+1)%4==0)
			printf("\n\t");
	}
	printf("};\n\n");

	printf("const uint Td3_r[] = {\n\t");
	for (int i=0; i<256; i++) {
		printf("0x%08XU, ", SWAP32(Td3[i]));
		if ((i+1)%4==0)
			printf("\n\t");
	}
	printf("};\n\n");
	*/
	enum mode { ENC = 100, DEC = 101 };

	int alg = 0;
	int repeat = 0;
	mode m;

	if (argc != 4) {
		usage();
		return -1;
	}

	for (int i=1; i<argc; i++) {
		if (starts_with(argv[i], "--algorithm="))
			alg = atoi(argv[i] + strlen("--algorithm="));
		else if (starts_with(argv[i], "--repeat="))
			repeat = atoi(argv[i] + strlen("--repeat="));
		else if (strcmp(argv[i], "-e") == 0)
			m = ENC;
		else if (strcmp(argv[i], "-d") == 0)
			m = DEC;
	}

	if (m != ENC && m != DEC) {
		usage();
		return -1;
	}

	if (alg != 0 && alg != 1) {
		usage();
		return -1;
	}

	if (repeat <= 0) {
		usage();
		return -1;
	}

    for (int i=0; i<repeat; i++) {
        const char* key = "\x54\x68\x61\x74\x73\x20\x6D\x79\x20\x4B\x75\x6E\x67\x20\x46\x75";
        const char* c   = "\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A";
        uchar* data = new uchar[16];
        uchar* cipher = new uchar[16];
        memset(data, 0, 16);
        memset(cipher, 0, 16);

        strcpy((char*)data, "Two One Nine Two");
        memcpy(cipher, c, 16);

        if (alg == ALG_ORIG) {
	        uint* rk = new uint[44];
	        memset(rk, 0, 4 * 44);

	        if (m == ENC) {
	        	rijndaelKeySetupEnc(rk, (uchar*)key);
	        	aes_encrypt(rk, data, cipher);
	        }
	        else if (m == DEC) {
	        	rijndaelKeySetupDec(rk, (uchar*)key);
	        	aes_decrypt(rk, cipher, data);
	        }
	        delete [] rk;
        }
        else if (alg == ALG_V1) {
        	// aes_encrypt_v1(data, cipher, (uchar*)key);
        	if (m == DEC) {
        		aes_decrypt_v1_reverse(cipher, data, (uchar*)key);
        	}
        }
        
        delete [] data;
        delete [] cipher;
    }
    return 0;
}
