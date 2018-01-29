#pragma once

#include <stdint.h>
#include "sm3.h"

#define AES_KEY_LENGTH 16
#define CLIENT_HELLO_MAGIC 0x23333333
#define RSA_KEY_LENGTH 256

#define SERVER_HELLO_MAGIC 0x66666666

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
};

extern "C" void initCheck(char* src, size_t len);