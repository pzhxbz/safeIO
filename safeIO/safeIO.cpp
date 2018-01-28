#include "safeIO_t.h"

#include "sgx_trts.h"

#include "sm3.h"
#include "sm4.h"
#include "init_check.h"


void sendEncrypt(char* src, char* des, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		des[i] = src[i] ^ 0xde;
	}

}

void recvDecrypt(char* src, char* des, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		des[i] = src[i] ^ 0xad;
	}
}

void ReadFileDecrypt(char* src, char* des, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		des[i] = src[i] ^ 0xbe;
	}
}

void SendtoEncrypt(char* src, char* des, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		des[i] = src[i] ^ 0xef;
	}
}

void recvfromDecrypt(char* src, char* des, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		des[i] = src[i] ^ 0xef;
	}
}