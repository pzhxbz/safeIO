// hookdl.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "hookdl.h"
#include "sgx_process.h"
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <algorithm>
#include <string>
#include <fstream>
#include <WS2tcpip.h>


#pragma comment(lib, "ws2_32.lib")
#define HOOK_NET_MODULE (L"ws2_32.dll")
#define HOOK_FILE_MODULE (L"kernel32.dll")
#define JMP_LENGTH 6

BYTE jmp[JMP_LENGTH] = { 0xe9,0x00, 0x00, 0x00, 0x00 ,0xc3 };
BYTE sendHook[JMP_LENGTH] = { 0 };
BYTE recvHook[JMP_LENGTH] = { 0 };
BYTE sendtoHook[JMP_LENGTH] = { 0 };
BYTE readFileHook[JMP_LENGTH] = { 0 };
BYTE createFileHook[JMP_LENGTH] = { 0 };
BYTE createFileAHook[JMP_LENGTH] = { 0 };
BYTE closeHandleHook[JMP_LENGTH] = { 0 };
BYTE recvfromHook[JMP_LENGTH] = { 0 };


std::list<HANDLE> fileHandles;
std::list<std::string> fileDecryptList;



bool initFileList()
{
	std::ifstream fileList("filelist.txt");
	if (!fileList.is_open())
	{
		return false;
	}
	while (!fileList.eof())
	{
		char filename[256] = { 0 };
		fileList.getline(filename, 256);
		fileDecryptList.push_back(std::string(filename));
		printf_s("%s\n", filename);
	}
	return true;
}


void initHook()
{
	HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, sendHook);
	HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, recvHook);
	HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, sendtoHook);
	HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, recvfromHook);
	HookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID)safe_ReadFile, readFileHook);
	HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
	HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, createFileAHook);
	HookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID)safe_CloseHandle, closeHandleHook);
}

void destoryHook()
{
	UnHookFunction(HOOK_NET_MODULE, "send", sendHook);
	UnHookFunction(HOOK_NET_MODULE, "recv", recvHook);
	UnHookFunction(HOOK_NET_MODULE, "sendto", sendtoHook);
	UnHookFunction(HOOK_NET_MODULE, "recvfrom", recvfromHook);
	UnHookFunction(HOOK_FILE_MODULE, "ReadFile", readFileHook);
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileW", createFileHook);
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileA", createFileAHook);
	UnHookFunction(HOOK_FILE_MODULE, "CloseHandle", closeHandleHook);
}


DWORD HookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	if (dwAddr == 0)
	{
		printf_s("can't find %s addr\n", lpFuncName);
		printf_s("0x%x\n", GetModuleHandle((LPCWSTR)lpModule));
		return 0;
	}
	//printf_s("find %s addr : 0x%x\n", lpFuncName, dwAddr);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0);
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	return dwAddr;
}

BOOL UnHookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
		return TRUE;
	return FALSE;
}

int WINAPI safe_send(SOCKET s, const char * buf, int len, int flags)
{
	UnHookFunction(HOOK_NET_MODULE, "send", sendHook);

	char* encryptBuf = (char*)malloc(len);

	sgx_sendEncrypt((char*)buf, encryptBuf, len);

	int returnValue = send(s, encryptBuf, len, flags);
	free(encryptBuf);
	HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, sendHook);
	return returnValue;
}

int WINAPI safe_recv(SOCKET s, char * buf, int len, int flags)
{
	UnHookFunction(HOOK_NET_MODULE, "recv", recvHook);

	char* decryptBuf = (char*)malloc(len);

	int returnValue = recv(s, decryptBuf, len, flags);

	sgx_recvDecrypt(decryptBuf, buf, len);

	HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, recvHook);

	free(decryptBuf);

	return returnValue;
}


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
	UnHookFunction(HOOK_NET_MODULE, "send", sendHook);

	int returnValue = send(s, buf, len, flags);

	HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, sendHook);
	return returnValue;
}

int unsafe_recv(int s, char * buf, int len, int flags)
{
	UnHookFunction(HOOK_NET_MODULE, "recv", recvHook);

	int returnValue = recv(s, buf, len, flags);

	HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, recvHook);

	return returnValue;
}

int unsafe_closesocket(int s)
{
	return closesocket(s);
}

int WINAPI safe_sendto(SOCKET s, const char * buf, int len, int flags, const sockaddr * to, int tolen)
{
	UnHookFunction(HOOK_NET_MODULE, "sendto", sendtoHook);

	char* encryptBuf = (char*)malloc(len);
	sgx_SendtoEncrypt((char*)buf, encryptBuf, len);

	int returnValue = sendto(s, encryptBuf, len, flags, to, tolen);

	free(encryptBuf);

	HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, sendtoHook);
	return returnValue;
}

int WINAPI safe_recvfrom(SOCKET s, char * buf, int len, int flags, sockaddr * from, int * fromlen)
{
	UnHookFunction(HOOK_NET_MODULE, "recvfrom", recvfromHook);

	char* decryptBuf = (char*)malloc(len);
	int returnValue = recvfrom(s, decryptBuf, len, flags, from, fromlen);
	sgx_recvfromDecrypt(decryptBuf, buf, len);
	free(decryptBuf);
	HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, recvfromHook);
	return returnValue;
}

int unsafe_sendto(int s, const char * buf, int len, int flags, const sockaddr * to, int tolen)
{
	UnHookFunction(HOOK_NET_MODULE, "sendto", sendtoHook);

	int returnValue = sendto(s, buf, len, flags, to, tolen);

	HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, sendtoHook);
	return returnValue;
}

int unsafe_recvfrom(int s, char * buf, int len, int flags, sockaddr * from, int * fromlen)
{
	UnHookFunction(HOOK_NET_MODULE, "recvfrom", recvfromHook);

	int returnValue = recvfrom(s, buf, len, flags, from, fromlen);

	HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, recvfromHook);
	return returnValue;
}

BOOL WINAPI safe_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	UnHookFunction(HOOK_FILE_MODULE, "ReadFile", readFileHook);


	BOOL returnValue;
	if (std::find(fileHandles.begin(), fileHandles.end(), hFile) != fileHandles.end())
	{
		char * decryptBuf = (char*)malloc(nNumberOfBytesToRead);
		returnValue = ReadFile(hFile, (LPVOID)decryptBuf, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
		sgx_ReadFileDecrypt(decryptBuf, (char*)lpBuffer, nNumberOfBytesToRead);
		free(decryptBuf);
		// printf("file read : %d\n", nNumberOfBytesToRead);
	}
	else
	{
		returnValue = ReadFile(hFile, (LPVOID)lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	HookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID)safe_ReadFile, readFileHook);
	return returnValue;
}

HANDLE WINAPI safe_CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileW", createFileHook);
	HANDLE returnValue = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (returnValue == INVALID_HANDLE_VALUE)
	{
		HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
		return returnValue;
	}
	auto it = fileDecryptList.begin();
	while (it != fileDecryptList.end())
	{
		if (wcsstr(lpFileName, (LPCTSTR)(it->c_str())))
		{
			fileHandles.push_back(returnValue);
			break;
		}
		it++;
	}
	wprintf(L"create filew: %s\n", lpFileName);
	HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
	return returnValue;
}

HANDLE WINAPI safe_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileA", createFileAHook);
	HANDLE returnValue = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (returnValue == INVALID_HANDLE_VALUE)
	{
		HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, createFileAHook);
		return returnValue;
	}
	auto it = fileDecryptList.begin();
	//printf("create file: %s\n", lpFileName);
	while (it != fileDecryptList.end())
	{
		if (strstr(lpFileName, it->c_str()))
		{
			fileHandles.push_back(returnValue);
			printf("create file get: %s\n", lpFileName);
			break;
		}
		it++;
	}

	HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, createFileAHook);
	return returnValue;
}

BOOL WINAPI safe_CloseHandle(HANDLE hObject)
{
	UnHookFunction(HOOK_FILE_MODULE, "CloseHandle", closeHandleHook);

	BOOL returnValue = CloseHandle(hObject);
	fileHandles.remove(hObject);

	HookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID)safe_CloseHandle, closeHandleHook);
	return returnValue;
}

