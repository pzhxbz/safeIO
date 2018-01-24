// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� HOOKDL_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// HOOKDL_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
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

bool initializeEnclave();
bool destroyEnclave();

void initHook();
void destoryHook();

bool initFileList();