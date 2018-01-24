// loader.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>

#define MAX_PATH_SIZE 512
#define HOOK_DLL L"hookdl.dll"


HANDLE processHandle;
HANDLE processThread;

int SetDebugPrivileges(void)
{
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL) == 0)
			{
				printf("AdjustTokenPrivilege Error! [%u]\n", GetLastError());
			}
		}

		CloseHandle(hToken);
	}
	return GetLastError();
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}
	//_tprintf(L"hProcess:%x\n", hProcess);

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	//_tprintf(L"pRemoteBuf:%x\n", pRemoteBuf);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	//printf("%s\n", szDllPath);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
	//	_tprintf(L"pThreadProc:%x\n", pThreadProc);

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, CREATE_SUSPENDED, NULL);

	//CloseHandle(hThread);
	//CloseHandle(hProcess);
	ResumeThread(processHandle);

	ResumeThread(hProcess);
	ResumeThread(hThread);  // start inject thread
	//WaitForSingleObject(hThread, INFINITE);
	Sleep(15);
	ResumeThread(processThread);  // start main thread
	return TRUE;

}

DWORD StartProcess(wchar_t* path)
{
	PROCESS_INFORMATION processInfo;
	STARTUPINFO startInfo;

	ZeroMemory(&processInfo, sizeof(processInfo));


	ZeroMemory(&startInfo, sizeof(startInfo));

	//startInfo.cb = sizeof(startInfo);

	//startInfo.wShowWindow = SW_SHOW;
	//startInfo.dwFlags = STARTF_USESHOWWINDOW;

	if (CreateProcess(
		NULL,
		(LPWSTR)path,
		NULL,
		NULL,
		false,
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE, //CREATE_NEW_CONSOLE  CREATE_SUSPENDED  wait for hook 
		NULL,
		NULL,
		&startInfo,
		&processInfo
	))
	{
		//CloseHandle(processInfo.hProcess);
		//CloseHandle(processInfo.hThread);
		processHandle = processInfo.hProcess;
		processThread = processInfo.hThread;
		return (WORD)processInfo.dwProcessId;
	}
	else
	{
		return 0;
	}
}


int wmain(int argc, wchar_t** argv)
{
	if (argc < 2)
	{
		_tprintf(L"usage [].exe <args>...\n");
		return 0;
	}

	wchar_t* path = (wchar_t*)malloc(MAX_PATH_SIZE * sizeof(wchar_t));
	path[0] = 0;

	for (int i = 1; i < argc; i++)
	{
		if (wcslen(path) + wcslen(argv[i]) >= MAX_PATH_SIZE)
		{
			break;
		}

		wcscat_s(path, MAX_PATH_SIZE, argv[i]);
		wcscat_s(path, MAX_PATH_SIZE, L" ");
	}
	//wsprintf(path, L"calc.exe");
	SetDebugPrivileges();
	DWORD pid = StartProcess(path);



	if (pid == 0)
	{
		_tprintf(L"failed to create process\n");
		return 0;
	}

	//_tprintf(L"%x\n", pid);

	//_tprintf(L"[+] Setting Debug Privileges [%ld]\n",);

	//	return 0;
	if (InjectDll(pid, HOOK_DLL))
	{
		_tprintf(L"success\n");

	}
	else
	{
		_tprintf(L"failed\n");
	}
	free(path);
	return 0;
}

