#pragma once
#include <windows.h>
#include <openssl/ec.h>
#include "romangol.h"
#include "ecc.h"

void sm2_sign(const_buf data, size_t len, buf signature, const_buf priKey, const Curve & curve);
bool sm2_verify(const_buf data, size_t len, buf signature, const EPoint & pubKey, const Curve & curve);


int SM2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);

