#pragma once
#include <windows.h>
#include <openssl/ec.h>


int SM2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);