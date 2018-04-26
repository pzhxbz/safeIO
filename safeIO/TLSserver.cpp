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

int serverShakeHand(SOCKET sockConn);
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
// just for test
char RsaPrivateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpQIBAAKCAQEAnOvAI4RlfQegd+MJLx7bGce77+/sAwk6YSG2ScraWjsJk4ZF\n\
Zw2JdJo/mhN10Hi5GmR75NAYXj1sdR60/nZMnc+pdve6XuKnGL5yo59xF4GoUiRB\n\
zkouFPYM8Eidmik0zoADaPbQw/ve+h3YTEsslHjpHE+1vt1XyS5+7yIkjAvcFMDN\n\
AafT/CsIqvuWIwgeDK0TwJNqtfUWGDv192ekhW996whxS0OLNWZOXiCOmvh6K3q5\n\
FBGPcYpgwZb0eSOux0gCf8mzB4BFnJ2LkFe+oIqPQU7PD4gyF6wv1Pw2pgwpPIVO\n\
0qWtW+VrHv9WrH+kryuR1mvP/uiDHKIZf0DJuQIDAQABAoIBAQCNFtb52Deb9DiO\n\
sn52dIrRIinTcOfGTwzDepk4vgAXcs+IagiKwLwfL/URpn+egn0Dwuc2cvgF+7pB\n\
j+tyg5EdrzISemiCmc1dzRasEVaQqQ5bVKgqP74xMI2vmcrCalxFcwod3RUVsafp\n\
QN5SsqCRmikWQIEL7F3a0Ehm4E717udWbGJ7tJq0F+I8NCg+1g5bYUz2wc6NTL9d\n\
ZfU9GoA6lMmJK47d0SevSe0sVrIbVtFxUBwvw4Uvfb/TUVsAm1Evb3YOxkPmHWPV\n\
DxWROZnzbH6GFe3eIg4dVVsjO27ESziFlxBQ/XhJRfXS9OpnPmA4THMBCdGcoPQ3\n\
7qF5BCYVAoGBAM22enfQapOSneSYNljawu+3U56RmmB6lwqIGVEKvIULWQkS0bbA\n\
6bk9EhwFhT7TgamAImdTTEwsZ6Zr1tDyhmyrtEDdVNNthZavhtTGPW5wT8uTLqvu\n\
Nn8bAXjJB5THduV1Q0P18SfBvMdT0bYe6sRsIu9SrEGy9ehsyaClES37AoGBAMNH\n\
3w9YZ5QO8s4ltfdsNOj0PzPQ2ILlT2JId4qzZnpzU92Rr0aIJM1QrRVPhdxidGaI\n\
UBaz+i3XyOQL2GobWfVZnkW04DbtweadzCn3HqyikPobClLbzrCEgkHG+bPM6OAl\n\
iRoAo7Y346ljxpmYyFs9JN5Sxf702dUhMuEl5RzbAoGBALP27hEfnf1YiRVRLEpz\n\
p5J7eYYBr2K0HKs0AaHqmJ50HQJZGmqdPlu117/3/GfINWkKFg76yobhWhQ3x4io\n\
g31SgbE1cF4/NF1tVbGTdG7Hhqd8LZpwHfD4uULn69/22EdJXP15je3QCcz/wTlo\n\
ts38JFvmoZggbg1WDtahUfQ9AoGBAMF4Fi1c15mfSb0lLWfJI45cVbWfRrJAP2rP\n\
Aug+ntvYIJGWwUEups9nC2Pemm9id5IRoM8tVkJO0+/jMHDHUlO6iwzii3TAD2fM\n\
lDZLZ29/zASN/6dhsB+/2FEUsdUJwPo5FeDWG1vveTUb7enErVN/e2RsO09CBAKc\n\
1oyrf5cbAoGAZYq+wgWlclLtuW0JDVGvnXnuM70Wi+f8BqPX+mBCFrsJx4Uh2rK0\n\
teO6Eehu4YoJCydp1Sw5nPlhzmYxyFeaTa0iGAqAjkdwwx1cXt4YSi9l+QLRzTUD\n\
a7MnVa1FriC11oWITzv5xVhIOq4shA0Tf+jujoN9Nmuiz5uiGTK4kvs=\n\
-----END RSA PRIVATE KEY-----";
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

int serverShakeHand(SOCKET sockConn)
{
	char sendBuf[256], recvBuf[256];
	recv(sockConn, recvBuf, 256, 0);
	if (strcmp(recvBuf, "TLS v1.2")) return 1; // closesocket(sockConn);
	
	recv(sockConn, recvBuf, 256, 0);
	if (strcmp(recvBuf, "sm3, sm4")) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 256, 0);
	char *clientRandom = recvBuf; 

	sprintf(sendBuf, "TLS v1.2");
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
	sprintf(sendBuf, "sm3, sm4");
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);

	char serverRandom[128];
	for (int i = 0; i < 127; i++) serverRandom[i] = (rand() % 0xff) + 1;
	serverRandom[127] = 0
	sprintf(sendBuf, serverRandom);
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
	sprintf(sendBuf, RsaPublicKey);
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);

	recv(sockConn, recvBuf, 256, 0);
	// preMasterKey = decrypt(recvBuf, priKey)
	// key sessionKey = genKey(preMasterKey, clientKey, serverKey);
	recv(sockConn, recvBuf, 256, 0);
	if (recvBuf != changeCipherSpec) return 1; // closesocket(sockConn);

	recv(sockConn, recvBuf, 256, 0);
	if (strcmp(decrypt(recvBuf, sessionKey), "Finished")) return 1; // closesocket(sockConn);
			
	recv(sockConn, recvBuf, 256, 0);
	if (strcmp(sm3(recvAll), decrypt(recv, sessionKey)) return 1; // closesocket(sockConn);

	sprintf(sendBuf, "%d", changeCipherSpec);
	send(sockConn, sendBuf, strlen(sendBuf) + 1, 0);
	// send encrypt(sm3(sendAll), sessionKey);
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