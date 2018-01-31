// dlltest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define DLL_NAME L"hookdl.dll"
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

void testSocket()
{
	int sock = 0;
	unsafe_initSocket(&sock, "127.0.0.1", 9999);
	send(sock, "test", 5, 0);
	char s[128] = { 0 };
	recv(sock, s, 128, 0);
	closesocket(sock);
}

void testReadFile()
{
	HANDLE programHandle = CreateFileA("de.py", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);


	size_t programSize = GetFileSize(programHandle, NULL);
	unsigned char* program = (unsigned char*)malloc(programSize + 100);
	DWORD last = 0;
	ReadFile(programHandle, program, programSize, &last, NULL);

	CloseHandle(programHandle);
	printf("%s", program);
	free(program);
}

int main()
{
	HANDLE lib = LoadLibrary(DLL_NAME);
	testReadFile();
	return 0;
}

