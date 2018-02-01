
#include "init_check.h"
#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "safeIO_t.h"
#include "sm4.h"
static uint8_t sm3Hash[SM3_DIGEST_LENGTH] = { 0 };

static uint8_t sessionKey[AES_KEY_LENGTH] = { 0 };

static int isVerify = 0;

static int token = -1;

static char fileKey[] = "thisisthetestkey";

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
		free(encrptyData);
		return;
	}
	int initReturn;
	int socket;
	unsafe_initSocket(&initReturn, &socket, "127.0.0.1", 6786);
	if (socket <= 0)
	{
		free(encrptyData);
		return;
		// create socket failed
	}
	unsafe_send(&initReturn, socket, (char*)encrptyData, enLen, 0);
	memset(encrptyData, 0, enLen);
	unsafe_recv(&initReturn, socket, (char*)encrptyData, 256, 0);
	unsigned char* decrptyData = (unsigned char*)malloc(rsaSize);
	//RSA_public_decrypt(rsaSize, encrptyData, decrptyData, rsa, RSA_PKCS1_PADDING);

	sm4_decrypt_ecb(encrptyData, initReturn, decrptyData, sessionKey);

	free(encrptyData);
	ServerHello* recvMessage = (ServerHello*)decrptyData;

	if (recvMessage->magic != SERVER_HELLO_MAGIC)
	{
		free(decrptyData);
		return;
	}

	if (memcmp(recvMessage->aesKey, sessionKey, AES_KEY_LENGTH) != 0)
	{
		free(decrptyData);
		return;
	}

	isVerify = recvMessage->isVerify;
	token = recvMessage->token;
	unsafe_closesocket(&initReturn, socket);


}


void initCheck(char * src, size_t len, int* results)
{

	sm3((const uint8_t*)src, len, sm3Hash);
	initAttestation();
	*results = isVerify;
}


unsigned char* getKey()
{
	return sessionKey;
}

int getToken()
{
	return token;
}
int getVerify()
{
	return isVerify;
}

uint8_t* getFileDecryptKey()
{
	return (uint8_t*)fileKey;
}