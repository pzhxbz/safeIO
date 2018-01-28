
#include "init_check.h"
#include <stdlib.h>
#include <sgx_trts.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "safeIO_t.h"

uint8_t sm3Hash[SM3_DIGEST_LENGTH] = { 0 };

uint8_t sessionKey[AES_KEY_LENGTH] = { 0 };

static bool isVerify = 0;


char RsaPublicKey[] = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOvAI4RlfQegd+MJLx7b\n\
Gce77+/sAwk6YSG2ScraWjsJk4ZFZw2JdJo/mhN10Hi5GmR75NAYXj1sdR60/nZM\n\
nc+pdve6XuKnGL5yo59xF4GoUiRBzkouFPYM8Eidmik0zoADaPbQw/ve+h3YTEss\n\
lHjpHE+1vt1XyS5+7yIkjAvcFMDNAafT/CsIqvuWIwgeDK0TwJNqtfUWGDv192ek\n\
hW996whxS0OLNWZOXiCOmvh6K3q5FBGPcYpgwZb0eSOux0gCf8mzB4BFnJ2LkFe+\n\
oIqPQU7PD4gyF6wv1Pw2pgwpPIVO0qWtW+VrHv9WrH+kryuR1mvP/uiDHKIZf0DJ\n\
uQIDAQAB\n\
-----END PUBLIC KEY-----\n";

void initAttestation()
{
	sgx_read_rand(sessionKey, AES_KEY_LENGTH);

	ClientHello message;
	message.magic = CLIENT_HELLO_MAGIC;
	memcpy(message.programHash, sm3Hash, SM3_DIGEST_LENGTH);
	memcpy(message.aesKey, sessionKey, AES_KEY_LENGTH);
	int size = 0;

	BIO* bio = BIO_new_mem_buf(RsaPublicKey, -1);

	RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

	if (rsa == NULL)
	{
		ERR_load_BIO_strings();
		char buf[512];
		ERR_error_string_n(ERR_get_error(), buf, 512);
		BIO_free(bio);
		return;
	}

	size_t rsaSize = RSA_size(rsa);

	unsigned char* encrptyData = (unsigned char*)malloc(rsaSize);

	int enLen = RSA_public_encrypt(sizeof(ClientHello), (unsigned char*)&message, encrptyData, rsa, RSA_PKCS1_PADDING);
	RSA_free(rsa);
	BIO_free(bio);
	if (enLen < 0)
	{
		// failed
		return;
	}
	int initReturn;
	int socket;
	unsafe_initSocket(&initReturn, &socket, "127.0.0.1", 6786);
	if (socket <= 0)
	{
		return;
		// create socket failed
	}
	unsafe_send(&initReturn, socket, (char*)encrptyData, enLen, 0);
	memset(encrptyData, 0, enLen);
	unsafe_recv(&initReturn, socket, (char*)encrptyData, 256, 0);

	unsafe_closesocket(&initReturn, socket);


}


void initCheck(char * src, size_t len)
{

	sm3((const uint8_t*)src, len, sm3Hash);
	initAttestation();
}


