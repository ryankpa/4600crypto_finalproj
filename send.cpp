/*
Author: Ryan Atienza
Class: CS 4600 - Crypto and InfoSec

SEND.CPP
This program takes in <#> command line arguments:
	argv[1]	- path to plaintext for encryption
	...
*/
#include <stdlib.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define countof(array) (sizeof(array) / sizeof(array[0]))

using namespace std;

// function prototypes
void encryptMessage(FILE* plaintext, FILE* transmitted_msg);
int AESEncrypt(FILE* in, FILE* out, unsigned char* key, unsigned char* iv);
// for debugging
int AESDecrypt(FILE* in, FILE* out, unsigned char* key, unsigned char* iv);

int main(int argc, char* argv[]) {
	FILE* plaintext, * transmitted_msg;
	errno_t err;	// for use with fopen_s

	// opening files for input/writing
	err = fopen_s(&plaintext, argv[1], "r");
	if (plaintext == NULL) perror("Error opening file");
	// truncating '.txt. from filename
	int slash_pos = 0;
	for (int i = 0; i < strlen(argv[1]); i++)
		if (argv[1][i] == '\\')
			slash_pos = i + 1;
	char new_filename[100];
	strncpy_s(new_filename, countof(new_filename), argv[1] + slash_pos, strlen(argv[1] + slash_pos) - 4);
	strcat_s(new_filename, countof(new_filename), "_encrypted.txt");
	err = fopen_s(&transmitted_msg, new_filename, "w+");
	encryptMessage(plaintext, transmitted_msg);
	// closing files
	err = fclose(plaintext);
	err = fclose(transmitted_msg);
	/* EVP RSA STUFF
	make use of EVP functions!
	EVP_PKEY* pkey;
	pkey = EVP_PKEY_new();
	this stuff generates an RSA public key
	EVP_PKEY_CTX* ctx2 = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(ctx2);
	EVP_PKEY_keygen(ctx2, &pkey);
	BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
	EVP_PKEY_print_public(out, pkey, 1, NULL);
	*/
	return 0;
}

void encryptMessage(FILE* plaintext, FILE* transmitted_msg) {
	// AES keygen
	unsigned char AESkey[16], iv[16];
	RAND_bytes(AESkey, sizeof AESkey);
	RAND_bytes(iv, sizeof iv);

	AESEncrypt(plaintext, transmitted_msg, AESkey, iv);
}
/*
AESEncryption():
	- borrows from openssl.org's encryption function example
	  which can be found here: https://www.openssl.org/docs/man1.0.2/man3/EVP_EncryptInit.html
*/
int AESEncrypt(FILE* in, FILE* out, unsigned char* key, unsigned char* iv) {
	/*setting up for AES encryption*/
	int inlen, outlen;
	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	/*encrypting*/
	for (;;) {
		inlen = fread(inbuf, 1, 1024, in);
		if (inlen <= 0) break;
		if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
			// cleanup cipher context due to error
			EVP_CIPHER_CTX_cleanup(ctx);
			return 0;
		}
		fwrite(outbuf, 1, outlen, out);
	}
	if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
		// cleanup cipher context due to error
		EVP_CIPHER_CTX_cleanup(ctx);
		return 0;
	}
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(ctx);
	return 0;
}
