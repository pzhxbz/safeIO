#include "stdafx.h"

#include "test_untrusted.h"
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
// _WINSOCK_DEPRECATED_NO_WARNINGS

int unsafe_initSocket(int * s, char * ip, int port)
{

	WORD sockVersion = MAKEWORD(2, 2);

	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return -1;
	}

	unsigned int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock == INVALID_SOCKET)
	{
		return -1;
	}

	sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	//inet_pton(AF_INET, ip, &serAddr.sin_addr);
	serAddr.sin_addr.S_un.S_addr = inet_addr(ip);

	serAddr.sin_port = htons(port);
	if (connect(sock, (sockaddr*)&serAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		closesocket(sock);
		return -1;
	}

	*s = sock;

	return 0;
}

int unsafe_send(int s, const char * buf, int len, int flags)
{

	int returnValue = send(s, buf, len, flags);

	return returnValue;
}

int unsafe_recv(int s, char * buf, int len, int flags)
{

	int returnValue = recv(s, buf, len, flags);

	return returnValue;
}

int unsafe_closesocket(int s)
{
	return closesocket(s);
}
int unsafe_sendto(int s, const char * buf, int len, int flags, const sockaddr * to, int tolen)
{

	int returnValue = sendto(s, buf, len, flags, to, tolen);

	return returnValue;
}

int unsafe_recvfrom(int s, char * buf, int len, int flags, sockaddr * from, int * fromlen)
{

	int returnValue = recvfrom(s, buf, len, flags, from, fromlen);

	return returnValue;
}