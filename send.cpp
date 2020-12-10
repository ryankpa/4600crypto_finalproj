/*
Author: Ryan Atienza
Class: CS 4600 - Crypto and InfoSec

SEND.CPP
This program takes in <#> command line arguments:
	argv[1]	- path to plaintext for encryption
	argv[2] - path to receiver's public key
	...
NOTES/TO-DOS:
	- check to see if it works with the receive program!
*/
#pragma warning(disable: 4996)	// included to let me use deprecated openssl functions
#include <stdlib.h>
#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define countof(array) (sizeof(array) / sizeof(array[0]))

using namespace std;

// function prototypes
void fileSetup(FILE* &plaintext, FILE* &transmitted_msg, char* argv[]);
int encryptMessage(FILE* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertxt);
int encryptAESKey(char* filename, unsigned char* AESkey, unsigned char* iv, unsigned char* encAES, unsigned char* encIV);
int generateHMAC(unsigned char* msg, int msglen, unsigned char* key, int keylen, unsigned char* hash);

int main(int argc, char* argv[]) {
	FILE* plaintext, * transmitted_msg;
	// opening files
	cout << "Opening files...\n";
	fileSetup(plaintext, transmitted_msg, argv);

	// message encryption
	cout << "Files opened. Encrypting message...\n";
	unsigned char AESkey[16], iv[16];
	unsigned char encryptedMsg[1024 + EVP_MAX_BLOCK_LENGTH];
	int encrypt_msg_len, encrypted_keys_len;
	encrypt_msg_len = encryptMessage(plaintext, AESkey, iv, encryptedMsg);

	// key encryption
	cout << "Message encryption done. Encrypting key...\n";
	unsigned char encAES[256], encIV[256];
	encrypted_keys_len = encryptAESKey(argv[2], AESkey, iv, encAES, encIV);

	//HMAC generation
	cout << "Key encryption done. Generating HMAC...\n";
	unsigned char hash[32];
	int hash_len;
	hash_len = generateHMAC(encryptedMsg, encrypt_msg_len, AESkey, 16, hash);

	// output everything to file transmitted_msg points to
	cout << "HMAC generation done. Writing to file...\n";
	string lengths;
	lengths.append(to_string(encrypt_msg_len)); lengths += " ";
	lengths.append(to_string(encrypted_keys_len)); lengths += " ";
	lengths.append(to_string(hash_len)); lengths += " ";
	fwrite(lengths.c_str(), 1, lengths.length(), transmitted_msg);
	fwrite(encryptedMsg, 1, encrypt_msg_len, transmitted_msg);
	fwrite(encAES, 1, 256, transmitted_msg);
	fwrite(encIV, 1, 256, transmitted_msg);
	fwrite(hash, 1, hash_len, transmitted_msg);

	// closing files
	cout << "Successfully written to file!\n";
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

/*
encryptMessage()
	- borrows from OpenSSL's encryption/decryption example
	  which can be found here: https://www.openssl.org/docs/man1.0.2/man3/EVP_EncryptInit.html
*/
int encryptMessage(FILE* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertxt) {
	// AES keygen
	RAND_bytes(key, sizeof key);
	RAND_bytes(iv, sizeof iv);
	// encrypting
	unsigned char inbuf[1024];
	int inlen, outlen = 0;
	int final_ciphertxt_len = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	for (;;) {
		inlen = fread(inbuf, 1, 1024, plaintext);
		if (inlen <= 0) break;
		EVP_EncryptUpdate(ctx, ciphertxt + outlen, &outlen, inbuf, inlen);
		final_ciphertxt_len += outlen;
	}
	EVP_EncryptFinal_ex(ctx, ciphertxt + outlen, &outlen);
	final_ciphertxt_len += outlen;
	EVP_CIPHER_CTX_free(ctx);
	return final_ciphertxt_len;
}

/*
encryptAESKey():
	- uses RSA encryption to encrypt the AES key and iv used to generate ciphertext
	- returns length of the two encrypted texts
	- reference used: https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
*/
int encryptAESKey(char* filename, unsigned char* AESkey, unsigned char* iv, unsigned char* encAES, unsigned char* encIV) {
	int encAES_len, encIV_len;
	// opening pub key
	FILE* pubkey_file;
	errno_t err = fopen_s(&pubkey_file, filename, "r");
	RSA* rsa;
	rsa = PEM_read_RSA_PUBKEY(pubkey_file, NULL, 0, NULL);
	// encrypting AES key
	encAES_len = RSA_public_encrypt(RSA_size(rsa), AESkey, encAES, rsa, RSA_NO_PADDING);
	// encrypt iv
	encIV_len = RSA_public_encrypt(RSA_size(rsa), iv, encIV, rsa, RSA_NO_PADDING);
	return (encAES_len + encIV_len);
}

/*
generateHMAC():
	- generates a HMAC for the encrypted message using SHA-256
	- references: 
		- https://www.openssl.org/docs/man1.1.0/man3/HMAC.html
	- the key used is the AES key
*/
int generateHMAC(unsigned char* msg, int msglen, unsigned char* key, int keylen, unsigned char* hash) {
	unsigned int digest_len;
	HMAC(EVP_sha256(), key, keylen, msg, msglen, hash, &digest_len);
	return digest_len;
}