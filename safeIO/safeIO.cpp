#include "safeIO_t.h"

#include "sgx_trts.h"

#include "sm3.h"
#include "sm4.h"
#include "init_check.h"
#include "cpp_int.h"

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

void cpp_int_test()
{
	cpp_int a("0x123");
	cpp_int b("243");
	cpp_int c = a*b;

	char s[1024] = { 0 };
	ToUint8(c, (uint8_t*)s);

	a = cpp_int::FromDec("666");
	b = cpp_int::FromDec("333");
	c = a + b;

	c = a%b;

}