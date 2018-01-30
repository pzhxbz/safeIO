#include "safeIO_t.h"

#include "sgx_trts.h"

#include "sm3.h"
#include "sm4.h"
#include "init_check.h"
#include "cpp_int.h"

void sendEncrypt(char* src, char* des, size_t len)
{
	//	for (size_t i = 0; i < len; i++)
	//	{
	//		des[i] = src[i] ^ 0xde;
	//	}
	if (getVerify() != VERIFY_SUCCESS)
	{
		return;
	}
	*(int*)(des) = getToken();
	int realSize = len % SM4_BLOCK_SIZE == 0 ? len : \
		(len / SM4_BLOCK_SIZE)*SM4_BLOCK_SIZE + SM4_BLOCK_SIZE;
	char* tmpBuf = (char*)malloc(realSize);
	memset(tmpBuf, 0, realSize);
	memcpy(tmpBuf, src, len);
	sm4_encrypt_ecb((const uint8_t*)tmpBuf, realSize, (uint8_t*)&des[4], getKey());
	free(tmpBuf);
}

void recvDecrypt(char* src, char* des, size_t len)
{
	if (getVerify() != VERIFY_SUCCESS)
	{
		return;
	}
	sm4_decrypt_ecb((const uint8_t*)src, len, (uint8_t*)des, getKey());
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