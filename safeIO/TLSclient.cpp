#include <stdio.h>  
#include <stdlib.h>
#include <time.h>
#include <Winsock2.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "sm3.h"
#include "sm4.h"
#pragma comment(lib,"WS2_32.lib")
#pragma warning(disable:4996)

int clientShakeHand(SOCKET sockClient);
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)

char RsaPublicKey[] = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOvAI4RlfQegd+MJLx7b\n\
Gce77+/sAwk6YSG2ScraWjsJk4ZFZw2JdJo/mhN10Hi5GmR75NAYXj1sdR60/nZM\n\
nc+pdve6XuKnGL5yo59xF4GoUiRBzkouFPYM8Eidmik0zoADaPbQw/ve+h3YTEss\n\
lHjpHE+1vt1XyS5+7yIkjAvcFMDNAafT/CsIqvuWIwgeDK0TwJNqtfUWGDv192ek\n\
hW996whxS0OLNWZOXiCOmvh6K3q5FBGPcYpgwZb0eSOux0gCf8mzB4BFnJ2LkFe+\n\
oIqPQU7PD4gyF6wv1Pw2pgwpPIVO0qWtW+VrHv9WrH+kryuR1mvP/uiDHKIZf0DJ\n\
uQIDAQAB\n\
-----END PUBLIC KEY-----\n";
int changeCipherSpec = 0xfe;
srand((unsigned)time(0));

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_create()) == NULL) handleErrors();
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) handleErrors();
	if (1 != EVP_DigestUpdate(mdctx, message, message_len)) handleErrors();
	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) handleErrors();
	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}

int clientShakeHand(SOCKET sockClient)
{
	char sendBuf[256], recvBuf[256];
	sprintf(sendBuf, "TLS v1.2");
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
	sprintf(sendBuf, "sm3, sm4");
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);

	char clientRandom[128];
	for (int i = 0; i < 127; i++) clientRandom[i] = (rand() % 0xff) + 1;
	clientRandom[127] = 0
	sprintf(sendBuf, clientRandom);
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);

	recv(sockClient, recvBuf, 256, 0);
	if (strcmp(recvBuf, "TLS v1.2")) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 256, 0);
	if (strcmp(recvBuf, "sm3, sm4")) return 1; // closesocket(sockConn);

	recv(sockClient, recvBuf, 256, 0);
	char* serverRandom = recvBuf;
	recv(sockClient, recvBuf, 256, 0);
	if (strcmp(recvBuf, RsaPublicKey)) return 1; // closesocket(sockConn);
		
	// send encrypt(preMasterKey, pubKey);
	// sessionKey = genKey(preMasterKey, clientKey, serverKey);
	sprintf(sendBuf, "%d", changeCipherSpec);
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
	// send encrypt("Finished", sessionKey);
	// send encrypt(sm3(sendAll), sessionKey);
	recv(sockClient, recvBuf, 256, 0);
	if (recvBuf != changeCipherSpec) return 1; // closesocket(sockConn);
		
	recv(sockClient, recvBuf, 256, 0);
	if (strcmp(sm3(sendAll), decrypt(recvBuf, sessionKey)) return 1; // closesocket(sockConn);

	return 0;
}

int main()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(1, 1);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		return 1;
	}

	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1) {
		WSACleanup();
		return 1;
	}
	SOCKET sockClient = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(6000);
	connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	if(!clientShakeHand(sockClient))
	{
		while (1)
		{
			//recv
			//recvMsg = dec(recv)
			//send enc(sendMsg)
		}
	}

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	
	/*
	send(sockClient, "hello", strlen("hello") + 1, 0);
	char recvBuf[50];
	recv(sockClient, recvBuf, 50, 0);
	printf("%s\n", recvBuf);
	*/
	closesocket(sockClient);
	WSACleanup();

	return 0;
}