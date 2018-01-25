// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 HOOKDL_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// HOOKDL_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef HOOKDL_EXPORTS
#define HOOKDL_API __declspec(dllexport)
#else
#define HOOKDL_API __declspec(dllimport)
#endif


#include <Windows.h>
#include <winsock2.h>
#include "sgx_urts.h"

// tcp hook
int WINAPI safe_send(SOCKET s, const char *buf, int len, int flags);
int WINAPI safe_recv(SOCKET s, char* buf, int len, int flags);

// udp hook
int WINAPI safe_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
int WINAPI safe_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);



BOOL WINAPI safe_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

HANDLE WINAPI safe_CreateFile(
	LPCTSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);
HANDLE WINAPI safe_CreateFileA(
	LPCSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);
BOOL WINAPI safe_CloseHandle(HANDLE hObject);


DWORD HookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup);
BOOL UnHookFunction(LPCWSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup);

void initHook();
void destoryHook();

bool initFileList();