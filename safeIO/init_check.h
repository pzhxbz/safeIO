#pragma once

#include <stdint.h>
#include "sm3.h"

#define AES_KEY_LENGTH 16
#define CLIENT_HELLO_MAGIC 0x23333333
#define RSA_KEY_LENGTH 256

#define SERVER_HELLO_MAGIC 0x66666666

#define NOT_VERIFY -1
#define VERIFY_SUCCESS 1
#define TOKEN_FLOW 2

struct ClientHello
{
	int magic;
	uint8_t aesKey[AES_KEY_LENGTH];
	uint8_t programHash[SM3_DIGEST_LENGTH];
};

struct ServerHello
{
	int magic;
	uint8_t aesKey[AES_KEY_LENGTH];
	int isVerify;
	int token;
};

extern "C" void initCheck(char* src, size_t len, int* results);

unsigned char* getKey();
int getToken();
int getVerify();
uint8_t* getFileDecryptKey();