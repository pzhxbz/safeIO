#include "sm2.h"
#include "ecc.h"
#include "cpp_int.h"
#include <windows.h>
#include <openssl/sha.h>
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>

void sha256(const uint8_t* buf, size_t len, uint8_t* des)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, len);
	SHA256_Final(des, &ctx);
}
void sm2_sign(const_buf data, size_t len, buf signature, const_buf priKey, const Curve & curve)
{
	// 1. hash the message
	sha256(data, len, signature);
	cpp_int hash = cpp_int::FromUint8(signature, SHA256_DIGEST_LENGTH);

	// 2. produce random 
	uint8_t tmp[CURVE_LEN];
	sgx_read_rand(tmp, sizeof(tmp));
	tmp[0] &= 0x7f;
	cpp_int k = cpp_int::FromUint8(tmp, sizeof(tmp));
	memset(tmp, 0, sizeof(tmp));

	// 3. sign
	cpp_int dA = cpp_int::FromUint8((uint8_t*)priKey, curve.blockLen);
	EPoint kG = mul(k, curve.G, curve);
	cpp_int r = mod(hash + kG.x, curve.n);
	cpp_int s = mod(inv_mod(1 + dA, curve.n) * (k - r * dA), curve.n);

	// std::cout << s << std::endl;

	// 4. export
	ToUint8(r, signature);
	ToUint8(s, signature + curve.blockLen);
}


bool sm2_verify(const_buf data, size_t len, buf signature, const EPoint & pubKey, const Curve & curve)
{
	// 1. recover parameters
	uint8_t hash[SHA256_DIGEST_LENGTH];
	sha256(data, len, hash);
	cpp_int sign = cpp_int::FromUint8(hash, SHA256_DIGEST_LENGTH);
	cpp_int r = cpp_int::FromUint8(signature, CURVE_LEN);
	cpp_int s = cpp_int::FromUint8(signature + CURVE_LEN, CURVE_LEN);

	// 2. verify sign
	cpp_int t = mod(r + s, curve.n);
	EPoint A = mul(s, curve.G, curve);
	EPoint B = mul(t, pubKey, curve);
	EPoint X = add(A, B, curve);

	return mod(sign + X.x, curve.n) == r;
}

int SM2_encrypt(int type, const unsigned char * in, size_t inlen, unsigned char * out, size_t * outlen, EC_KEY * ec_key)
{
	return 0;
}

int SM2_decrypt(int type, const unsigned char * in, size_t inlen, unsigned char * out, size_t * outlen, EC_KEY * ec_key)
{
	return 0;
}
