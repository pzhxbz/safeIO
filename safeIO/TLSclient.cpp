#include <stdio.h>  
#include <Winsock2.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#pragma comment(lib,"WS2_32.lib")
#pragma warning(disable:4996)

int changeCipherSpec = 0xfe

int clientShakeHand(SOCKET sockClient)
{
	// send TLS v1.2
	// send sm3, sm4
	// send rand1

	char recvBuf[50];
	recv(sockClient, recvBuf, 50, 0);
	if (strcmp(recvBuf, "TLS v1.2")) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 50, 0);
	if (strcmp(recvBuf, "sm3, sm4")) return 1; // closesocket(sockConn);

	recv(sockClient, recvBuf, 50, 0);
	// int rand2 = recvBuf;
	recv(sockClient, recvBuf, 50, 0);
	// key pubKey = recvBuf;
	// assert pubKey == serverPubKey
		
	// send encrypt(rand3, pubKey);
	// sessionKey = geneKey(rand1, rand2, rand3);
	// send 0xfe; /*ChangeCipherSpec*/
	// send encrypt("Finished", sessionKey);
	// send encrypt(sm3(sendedAll), sessionKey);
	recv(sockClient, recvBuf, 50, 0);
	if (recvBuf != changeCipherSpec) return 1; // closesocket(sockConn);
		
	recv(sockClient, recvBuf, 50, 0);
	if (strcmp(sm3(sendedAll), decrypt(recvBuf)) return 1; // closesocket(sockConn);

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