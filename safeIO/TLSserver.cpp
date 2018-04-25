#include <stdio.h>  
#include <Winsock2.h>  
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#pragma comment(lib,"WS2_32.lib") 
#pragma warning(disable:4996)

int changeCipherSpec = 0xfe

int serverShakeHand(SOCKET sockConn)
{
	char recvBuf[50];
	recv(sockConn, recvBuf, 50, 0);
	if (strcmp(recvBuf, "TLS v1.2")) return 1; // closesocket(sockConn);
	
	recv(sockConn, recvBuf, 50, 0);
	if (strcmp(recvBuf, "sm3, sm4")) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 50, 0);
	int rand1 = recvBuf;

	// send TLS v1.2
	// send sm3, sm4
	// send rand2
	// send pubKey

	recv(sockConn, recvBuf, 50, 0);
	// rand3 = decrypt(recvBuf, priKey)
	// key sessionKey = geneKey(rand1, rand2, rand3);
	recv(sockConn, recvBuf, 50, 0);
	if (recvBuf != changeCipherSpec) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 50, 0);
	if (strcmp(decrypt(recvBuf, sessionKey), "Finished")) return 1; // closesocket(sockConn);
			
	recv(sockConn, recvBuf, 50, 0);
	if (strcmp(sm3(recvAll), decrypt(recv)) return 1; // closesocket(sockConn);

	return 0;
}

int main()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(1, 1);

	err = WSAStartup(wVersionRequested, &wsaData);

	if (err != 0)
	{
		return 0;
	}

	if (LOBYTE(wsaData.wVersion) != 1 ||
		HIBYTE(wsaData.wVersion) != 1)
	{
		WSACleanup();
		return 0;
	}

	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addrSrv;
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(6000);
	bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	listen(sockSrv, 5);

	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);


	while (1)
	{
		SOCKET sockConn = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
		/*
		char sendBuf[50];
		sprintf(sendBuf, "Welcome %s to here!", inet_ntoa(addrClient.sin_addr));
		send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
		*/

		/* Load all digest and cipher algorithms */
		OpenSSL_add_all_algorithms();

		/* Load config file, and other important initialisation */
		OPENSSL_config(NULL);

		/* Load the human readable error strings for libcrypto */
		ERR_load_crypto_strings();

		
		if(!serverShakeHand(sockConn))
		{ 
			
			while (1)
			{
				//recv
				//recvMsg = dec(recv)
				//send enc(sendMsg)
			}

		}
		else
		{
			closesocket(sockConn);
		}
		
		/* Removes all digests and ciphers */
		EVP_cleanup();

		/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
		CRYPTO_cleanup_all_ex_data();

		/* Remove error strings */
		ERR_free_strings();

	}

	return 0;
}