/*
Author: Ryan Atienza
Class: CS 4600 - Crypto and InfoSec

SEND.CPP
This program takes in <#> command line arguments:
	argv[1]	- path to plaintext for encryption
	...
*/
#pragma warning(disable: 4996)	// included to let me use deprecated openssl functions
#include <stdlib.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

#define countof(array) (sizeof(array) / sizeof(array[0]))

using namespace std;

// function prototypes
void fileSetup(FILE* &plaintext, FILE* &transmitted_msg, char* argv[]);
void encryptMessage(FILE* plaintext, FILE* transmitted_msg, unsigned char* key, unsigned char* IV);
int AESEncrypt(FILE* in, FILE* out, unsigned char* key, unsigned char* iv);
void encryptAESKey(char* filename, unsigned char* AESkey, unsigned char* iv);

int main(int argc, char* argv[]) {
	FILE* plaintext, * transmitted_msg;
	unsigned char AESkey[16], iv[16];
	fileSetup(plaintext, transmitted_msg, argv);
	encryptMessage(plaintext, transmitted_msg, AESkey, iv);
	cout << "message encryption done\n";
	encryptAESKey(argv[2], AESkey, iv);
	// closing files
	errno_t err = fclose(plaintext);
	err = fclose(transmitted_msg);

	return 0;
}

// may add onto this...
void fileSetup(FILE* &plaintext, FILE* &transmitted_msg, char* argv[]) {
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
}

void encryptMessage(FILE* plaintext, FILE* transmitted_msg, unsigned char* key, unsigned char* IV) {
	// AES keygen
	unsigned char AESkey[16], iv[16];
	RAND_bytes(AESkey, sizeof AESkey);
	RAND_bytes(iv, sizeof iv);
	// storing AES key and iv
	memcpy(key, AESkey, 16);
	memcpy(IV, iv, 16);
	// encrypting
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

void encryptAESKey(char* filename, unsigned char* AESkey, unsigned char* iv) {
	unsigned char* encAES, *encIV;
	// opening pub key
	FILE* pubkey_file, *test_file;
	errno_t err = fopen_s(&pubkey_file, filename, "r");
	err = fopen_s(&test_file, "test.txt", "w+");
	RSA* rsa;
	rsa = PEM_read_RSA_PUBKEY(pubkey_file, NULL, 0, NULL);
	// encrypt AES key
	encAES = new unsigned char[RSA_size(rsa)];
	RSA_public_encrypt(RSA_size(rsa), AESkey, encAES, rsa, RSA_NO_PADDING);
	// encrypt iv
	// RSA_public_encrypt(RSA_size(rsa), iv, encIV, rsa, RSA_NO_PADDING);

	// FOR DEBUGGING: output encrypted AES and original AES
	fwrite(encAES, 1, 16, test_file);
	//fwrite("\n", 1, 1, test_file);
	//fwrite(encIV, 1, 16, test_file);
}