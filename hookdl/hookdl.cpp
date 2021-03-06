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
#include "safeIO_u.h"
#include <MinHook.h>

#ifdef _WIN32
#pragma comment(lib, "libMinHook-x86-v140-mdd.lib")
#endif // _WIN32

#ifdef _WIN64
#pragma comment(lib, "libMinHook-x64-v140-mdd.lib")
#endif // _WIN64



#pragma comment(lib, "ws2_32.lib")
#define HOOK_NET_MODULE (L"ws2_32.dll")
#define HOOK_FILE_MODULE (L"kernel32.dll")
// #define JMP_LENGTH 6

// BYTE jmp[JMP_LENGTH] = { 0xe9,0x00, 0x00, 0x00, 0x00 ,0xc3 };


typedef int (WINAPI *sendFunc)(SOCKET s, const char *buf, int len, int flags);
typedef int (WINAPI *recvFunc)(SOCKET s, char* buf, int len, int flags);
typedef int (WINAPI *sendtoFunc)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
typedef int (WINAPI *recvfromFunc)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
typedef BOOL(WINAPI *ReadFileFunc)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

typedef HANDLE(WINAPI *CreateFileFunc)(
	LPCTSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);
typedef HANDLE(WINAPI *CreateFileAFunc)(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);
typedef BOOL(WINAPI *CloseHandleFunc)(HANDLE hObject);


sendFunc sendHook = NULL;
recvFunc recvHook = NULL;
sendtoFunc sendtoHook = NULL;
ReadFileFunc readFileHook = NULL;
CreateFileFunc createFileHook = NULL;
CreateFileAFunc createFileAHook = NULL;
CloseHandleFunc closeHandleHook = NULL;
recvfromFunc recvfromHook = NULL;


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
	if (MH_Initialize() != MH_OK)
	{
		exit(-1);
	}
	HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, (LPVOID*)&sendHook);
	HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, (LPVOID*)&recvHook);
	HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, (LPVOID*)&sendtoHook);
	HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, (LPVOID*)&recvfromHook);
	HookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID)safe_ReadFile, (LPVOID*)&readFileHook);
	HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, (LPVOID*)&createFileHook);
	HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, (LPVOID*)&createFileAHook);
	HookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID)safe_CloseHandle, (LPVOID*)&closeHandleHook);
}

void destoryHook()
{
	MH_Uninitialize();
	UnHookFunction(HOOK_NET_MODULE, "send", (LPVOID*)&sendHook);
	UnHookFunction(HOOK_NET_MODULE, "recv", (LPVOID*)&recvHook);
	UnHookFunction(HOOK_NET_MODULE, "sendto", (LPVOID*)& sendtoHook);
	UnHookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID*)&recvfromHook);
	UnHookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID*)&readFileHook);
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID*)& createFileHook);
	UnHookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID*)&createFileAHook);
	UnHookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID*)&closeHandleHook);
}


int checkSendHooked()
{
	return 0;
	/*DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(HOOK_NET_MODULE), "send");
	if (dwAddr == 0)
	{
		printf_s("can't chk send hook\n");
		return 1;
	}
	BYTE tmp[6] = { 0 };
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, tmp, 6, 0);
	if (memcmp(tmp, sendHook, 6) == 0)
	{
		return 0;
	}
	return 1;*/
}
int checkReadFileHooked()
{
	return 0;
	/*DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(HOOK_FILE_MODULE), "ReadFile");
	if (dwAddr == 0)
	{
		printf_s("can't chk readfile hook\n");
		return 1;
	}
	BYTE tmp[6] = { 0 };
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, tmp, 6, 0);
	if (memcmp(tmp, readFileHook, 6) == 0)
	{
		return 0;
	}
	return 1;*/
}

DWORD HookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, LPVOID *lpBackup)
{

	MH_CreateHookApi(lpModule, lpFuncName, lpFunction, lpBackup);
	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		printf_s("can't create %s hook\n", lpFuncName);
		exit(-1);
	}
	return 1;
	//DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	//if (dwAddr == 0)
	//{
	//	printf_s("can't find %s addr\n", lpFuncName);
	//	printf_s("0x%x\n", GetModuleHandle((LPCWSTR)lpModule));
	//	return 0;
	//}
	////printf_s("find %s addr : 0x%x\n", lpFuncName, dwAddr);
	//ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0);
	//DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
	//memcpy(&jmp[1], &dwCalc, 4);
	//WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	//return dwAddr;
}

BOOL UnHookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, LPVOID *lpBackup)
{

	return MH_DisableHook(lpBackup) == MH_OK;
	/*DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
		return TRUE;
	return FALSE;*/
}


#define  SM4_BLOCK_SIZE 16
int WINAPI safe_send(SOCKET s, const char * buf, int len, int flags)
{

	//UnHookFunction(HOOK_NET_MODULE, "send", sendHook);

	size_t realLength = len % SM4_BLOCK_SIZE == 0 ? len + 4 : \
		(len / SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE + 4 + SM4_BLOCK_SIZE; // i don't think it's can easily understand
	char* encryptBuf = (char*)malloc(realLength);

	sgx_sendEncrypt((char*)buf, encryptBuf, len);

	int returnValue = sendHook(s, encryptBuf, realLength, flags);


	free(encryptBuf);
	//HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, sendHook);
	return returnValue;
}

int WINAPI safe_recv(SOCKET s, char * buf, int len, int flags)
{
	//UnHookFunction(HOOK_NET_MODULE, "recv", recvHook);

	char* decryptBuf = (char*)malloc(len);

	int returnValue = recvHook(s, decryptBuf, len, flags);

	sgx_recvDecrypt(decryptBuf, buf, len);

	//HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, recvHook);

	free(decryptBuf);

	return returnValue;
}


extern "C" int unsafe_initSocket(int * s, char * ip, int port)
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

extern "C" int unsafe_send(int s, char * buf, int len, int flags)
{
	//int isHooked = checkSendHooked();
	//if (!isHooked)
	//{
	//	return send(s, buf, len, flags);
	//}
	//UnHookFunction(HOOK_NET_MODULE, "send", sendHook);

	int returnValue = sendHook(s, buf, len, flags);

	//HookFunction(HOOK_NET_MODULE, "send", (LPVOID)safe_send, sendHook);
	return returnValue;
}

extern "C" int unsafe_recv(int s, char * buf, int len, int flags)
{
	//UnHookFunction(HOOK_NET_MODULE, "recv", recvHook);

	int returnValue = recvHook(s, buf, len, flags);

	//HookFunction(HOOK_NET_MODULE, "recv", (LPVOID)safe_recv, recvHook);

	return returnValue;
}

extern "C" int unsafe_closesocket(int s)
{
	return closesocket(s);
}

int WINAPI safe_sendto(SOCKET s, const char * buf, int len, int flags, const sockaddr * to, int tolen)
{
	//UnHookFunction(HOOK_NET_MODULE, "sendto", sendtoHook);

	char* encryptBuf = (char*)malloc(len);
	sgx_SendtoEncrypt((char*)buf, encryptBuf, len);

	int returnValue = sendtoHook(s, encryptBuf, len, flags, to, tolen);

	free(encryptBuf);

	//HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, sendtoHook);
	return returnValue;
}

int WINAPI safe_recvfrom(SOCKET s, char * buf, int len, int flags, sockaddr * from, int * fromlen)
{
	//UnHookFunction(HOOK_NET_MODULE, "recvfrom", recvfromHook);

	char* decryptBuf = (char*)malloc(len);
	int returnValue = recvfromHook(s, decryptBuf, len, flags, from, fromlen);
	sgx_recvfromDecrypt(decryptBuf, buf, len);
	free(decryptBuf);
	//HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, recvfromHook);
	return returnValue;
}

extern "C" int unsafe_sendto(int s, char * buf, int len, int flags, const sockaddr * to, int tolen)
{
	//UnHookFunction(HOOK_NET_MODULE, "sendto", sendtoHook);

	int returnValue = sendtoHook(s, buf, len, flags, to, tolen);

	//HookFunction(HOOK_NET_MODULE, "sendto", (LPVOID)safe_sendto, sendtoHook);
	return returnValue;
}

extern "C" int unsafe_recvfrom(int s, char * buf, int len, int flags, sockaddr * from, int * fromlen)
{
	//UnHookFunction(HOOK_NET_MODULE, "recvfrom", recvfromHook);

	int returnValue = recvfromHook(s, buf, len, flags, from, fromlen);

	//HookFunction(HOOK_NET_MODULE, "recvfrom", (LPVOID)safe_recvfrom, recvfromHook);
	return returnValue;
}

BOOL WINAPI safe_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	//UnHookFunction(HOOK_FILE_MODULE, "ReadFile", readFileHook);


	BOOL returnValue;
	if (std::find(fileHandles.begin(), fileHandles.end(), hFile) != fileHandles.end())
	{
		// printf("file read %x: %d\n", hFile, nNumberOfBytesToRead);
		int realSize = nNumberOfBytesToRead % SM4_BLOCK_SIZE == 0 ? nNumberOfBytesToRead : \
			(nNumberOfBytesToRead / SM4_BLOCK_SIZE)*SM4_BLOCK_SIZE + SM4_BLOCK_SIZE;
		char * decryptBuf = (char*)malloc(realSize);
		returnValue = readFileHook(hFile, (LPVOID)decryptBuf, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

		sgx_ReadFileDecrypt(decryptBuf, (char*)lpBuffer, nNumberOfBytesToRead);
		// printf("%s\n", decryptBuf);
		// Sleep(5000);
		free(decryptBuf);

	}
	else
	{
		returnValue = readFileHook(hFile, (LPVOID)lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
	//HookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID)safe_ReadFile, readFileHook);
	return returnValue;
}

HANDLE WINAPI safe_CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	//UnHookFunction(HOOK_FILE_MODULE, "CreateFileW", createFileHook);
	HANDLE returnValue = createFileHook(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (returnValue == INVALID_HANDLE_VALUE)
	{
		//HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
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
	//HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
	return returnValue;
}

HANDLE WINAPI safe_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	//UnHookFunction(HOOK_FILE_MODULE, "CreateFileA", createFileAHook);
	HANDLE returnValue = createFileAHook(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (returnValue == INVALID_HANDLE_VALUE)
	{
		//HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, createFileAHook);
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

	//HookFunction(HOOK_FILE_MODULE, "CreateFileA", (LPVOID)safe_CreateFileA, createFileAHook);
	return returnValue;
}

BOOL WINAPI safe_CloseHandle(HANDLE hObject)
{
	//UnHookFunction(HOOK_FILE_MODULE, "CloseHandle", closeHandleHook);

	BOOL returnValue = closeHandleHook(hObject);
	fileHandles.remove(hObject);

	//HookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID)safe_CloseHandle, closeHandleHook);
	return returnValue;
}




HANDLE  unsafe_CreateFile(
	LPCTSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	//UnHookFunction(HOOK_FILE_MODULE, "CreateFileW", createFileHook);
	HANDLE returnValue = createFileHook(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	//HookFunction(HOOK_FILE_MODULE, "CreateFileW", (LPVOID)safe_CreateFile, createFileHook);
	return returnValue;
}

BOOL  unsafe_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	//int isHooked = checkReadFileHooked();
	//if (!isHooked)
	//{
	//	return ReadFile(hFile, (LPVOID)lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);;
	//}
	//UnHookFunction(HOOK_FILE_MODULE, "ReadFile", readFileHook);


	BOOL returnValue;

	returnValue = readFileHook(hFile, (LPVOID)lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	//HookFunction(HOOK_FILE_MODULE, "ReadFile", (LPVOID)safe_ReadFile, readFileHook);
	return returnValue;
}


BOOL unsafe_CloseHandle(HANDLE hObject)
{
	//UnHookFunction(HOOK_FILE_MODULE, "CloseHandle", closeHandleHook);

	BOOL returnValue = closeHandleHook(hObject);

	//HookFunction(HOOK_FILE_MODULE, "CloseHandle", (LPVOID)safe_CloseHandle, closeHandleHook);
	return returnValue;
}
