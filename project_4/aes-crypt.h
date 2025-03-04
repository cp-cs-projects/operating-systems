
#ifndef AES_CRYPT_H
#define AES_CRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#define BLOCKSIZE 1024
#define FAILURE 0
#define SUCCESS 1

/* int do_crypt(FILE* in, FILE* out, int action, char* key_str)
 * Purpose: Perform cipher on in File* and place result in out File*
 * Args: FILE* in      : Input File Pointer
 *       FILE* out     : Output File Pointer
 *       int action    : Cipher action (1=encrypt, 0=decrypt, -1=pass-through (copy))
 *	 char* key_str : C-string containing passphrase from which key is derived
 * Return: FAILURE on error, SUCCESS on success
 */
extern int do_crypt(FILE* in, FILE* out, int action, char* key_str);

#endif
