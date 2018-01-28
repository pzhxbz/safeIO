#pragma once

#include <stdint.h>
#include "sm3.h"

#define AES_KEY_LENGTH 16
#define CLIENT_HELLO_MAGIC 0x23333333
#define RSA_KEY_LENGTH 256


struct ClientHello
{
	int magic;
	uint8_t aesKey[AES_KEY_LENGTH];
	uint8_t programHash[SM3_DIGEST_LENGTH];
};

extern "C" void initCheck(char* src, size_t len);