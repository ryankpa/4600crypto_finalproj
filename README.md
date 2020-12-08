# 4600crypto_finalproj
Implementing a partial secure communication system between two parties using OpenSSL; the local folder "simulates" the communication channel.

# Things to do:
- Make sure both parties can access each other's RSA public keys, and that they each have their own RSA private key.
- ~~SENDER: Given an input file, use AES with a unique key, iv pair to encrypt its contents.~~
- ~~SENDER: Encrypt the AES key and iv using the receiver's public key.~~
- SENDER: Generate a MAC for the message to be sent.
- SENDER: Append the ciphertext, encrypted AES key, and MAC together, and then write that to a file.
- RECEIVER: Extract the ciphertext, encrypted AES key, and MAC from sender's file.
- RECEIVER: Authenticate the message, decrypt the encrypted AES key.
- RECEIVER: Decrypt the ciphertext for reading.
