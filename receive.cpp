/*
Author: Ryan Atienza
Class: CS 4600 - Crypto and InfoSec

RECEIVE.CPP
This program takes in 3 command line arguments:
	argv[1]	- path to ciphertext for parsing and decryption
	argv[2] - path to receiver's private key
	argv[3] - name of the file to write decrypted message to

The sole purpose of this program is to parse the ciphertext from a sender using send.cpp
and both verify and decrypt the message contents. It mainly relies on OpenSSL functions.
*/
#pragma warning(disable: 4996)	// included to let me use deprecated openssl functions
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
using namespace std;

// function prototypes
void parseCiphertxt(char* filename, unsigned char* &enc_msg, unsigned char* &encAES, 
					unsigned char* &encIV, unsigned char* &MAC, int* &lengths);
int generateHMAC(unsigned char* msg, int msglen, unsigned char* key, int keylen, unsigned char* hash);
int decryptMessage(unsigned char* ciphertext, int cipher_len, unsigned char* key, unsigned char* iv, ofstream& out);
int decryptAESKey(unsigned char* encAES, unsigned char* encIV, unsigned char* decAES, unsigned char* decIV, char* filename);

int main(int argc, char* argv[]) {
	unsigned char* enc_msg, * encAES, * encIV, * MAC;	// buffers for the content in ciphertext
	int* lengths;	// 0 = message length, 1 = encrypted keys length, 2 = MAC length
	cout << "Parsing ciphertext...\n";
	parseCiphertxt(argv[1], enc_msg, encAES, encIV, MAC, lengths);

	// decrypt AES key and IV
	cout << "Parse complete. Decrypting AES key and IV...\n";
	unsigned char* decAES, * decIV;	// buffers for decryption results
	decAES = new unsigned char[lengths[1] / 2];
	decIV = new unsigned char[lengths[1] / 2];
	decryptAESKey(encAES, encIV, decAES, decIV, argv[2]);

	// verify MAC
	cout << "Key and IV decryption complete. Authenticating message...\n";
	unsigned char hash[32];	// buffer for result of HMAC function
	bool verified = true;
	generateHMAC(enc_msg, lengths[0], decAES, 16, hash);
	for (int i = 0; i < lengths[2]; i++)
		if (hash[i] != MAC[i]) {
			verified = false;
			break;
		}

	if (verified)
		cout << "The message has been authenticated successfully.\n";
	else {
		cout << "Unable to authenticate message. Aborting...\n";
		return 0;
	}
	
	// decrypting message and writing to file
	cout << "Decrypting the message...\n";
	ofstream out;
	out.open(argv[3], ios::binary);	// open/create file user specified to output to
	decryptMessage(enc_msg, lengths[0], decAES, decIV, out);
	cout << "Decryption complete!\n";

	return 0;
}

/*
parseCiphertxt():
	- takes in the name of the file containing the ciphertext to decrypt
	- stores the encrypted message, AES key and iv, and MAC in dedicated buffers
*/
void parseCiphertxt(char* filename, unsigned char* &enc_msg, unsigned char* &encAES,
					unsigned char* &encIV, unsigned char* &MAC, int*& lengths) {
	ifstream ciphertext;
	char buffer[256];
	ciphertext.open(filename, ios::binary);	// IMPORTANT! must open in binary mode to work properly
	// get lengths
	lengths = new int[3];
	ciphertext.getline(buffer, 256, ' ');
	lengths[0] = atoi(buffer);
	ciphertext.getline(buffer, 256, ' ');
	lengths[1] = atoi(buffer);
	ciphertext.getline(buffer, 256, ' ');
	lengths[2] = atoi(buffer);

	// get ciphertexts and MAC
	enc_msg = new unsigned char [lengths[0]];
	encAES = new unsigned char[lengths[1]/2];
	encIV = new unsigned char[lengths[1]/2];
	MAC = new unsigned char[lengths[2]];
	ciphertext.read((char*)enc_msg, lengths[0]);
	ciphertext.read((char*)encAES, lengths[1]/2);
	ciphertext.read((char*)encIV, lengths[1]/2);
	ciphertext.read((char*)MAC, lengths[2]);
}

/*
decryptAESKey():
	- takes in the encrypted AES key and iv, and path to user's private key
	- decrypted results are stored in dedicated buffers
	- returns the length of the decrypted keys
	- mirror of encryptAESKey() in send.cpp
*/
int decryptAESKey(unsigned char* encAES, unsigned char* encIV, unsigned char* decAES, unsigned char* decIV, char* filename) {
	int decAES_len, decIV_len;
	// opening priv key
	FILE* privkey_file;
	errno_t err = fopen_s(&privkey_file, filename, "r");
	RSA* rsa;
	rsa = PEM_read_RSAPrivateKey(privkey_file, NULL, 0, NULL);
	// decrypting AES key
	decAES_len = RSA_private_decrypt(RSA_size(rsa), encAES, decAES, rsa, RSA_NO_PADDING);
	// decrypt iv
	decIV_len = RSA_private_decrypt(RSA_size(rsa), encIV, decIV, rsa, RSA_NO_PADDING);
	return decAES_len + decIV_len;
}

/*
generateHMAC():
	- generates a HMAC for the encrypted message using SHA-256
	- references https://www.openssl.org/docs/man1.1.0/man3/HMAC.html
	- the key used is the AES key
	- same function as in send.cpp
*/
int generateHMAC(unsigned char* msg, int msglen, unsigned char* key, int keylen, unsigned char* hash) {
	unsigned int digest_len;
	HMAC(EVP_sha256(), key, keylen, msg, msglen, hash, &digest_len);
	return digest_len;
}

/*
decryptMessage():
	- borrows from openssl.org's encryption function example
	  which can be found here: https://www.openssl.org/docs/man1.0.2/man3/EVP_EncryptInit.html
	- takes in the ciphertext and the corresponding AES key and iv used to generate it; decrypts the message
	- writes decryption result to a file specified by the receiver; also returns plaintext length
	- mirrors encryptMessage() in send.cpp
*/
int decryptMessage(unsigned char* ciphertext, int cipher_len, unsigned char* key, unsigned char* iv, ofstream& out) {
	// decrypting
	unsigned char plaintext[1024];
	int outlen = 0;
	int final_ciphertxt_len = 0;

	// establishing cipher context and setting it to decrypt using 256 bit AES in cbc mode
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	// actual decryption work done here
	EVP_DecryptUpdate(ctx, plaintext + outlen, &outlen, ciphertext, cipher_len);
	final_ciphertxt_len += outlen;
	// finalize decryption
	EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
	final_ciphertxt_len += outlen;

	// freeing context and memory
	EVP_CIPHER_CTX_free(ctx);

	// write decryption result to file
	out.write((const char*)plaintext, final_ciphertxt_len);
	return final_ciphertxt_len;
}