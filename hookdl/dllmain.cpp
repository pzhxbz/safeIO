// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#include "hookdl.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h"
#include "sgx_tcrypto.h"
#include "sgx_process.h"
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//Sleep(10000);
		//printf_s("process init\n");
		initFileList();
		initHook();

		//printf_s("process init finish\n");

		break;
	case DLL_THREAD_ATTACH:
		//printf_s("thread init\n");
		//initHook();

		break;
	case DLL_THREAD_DETACH:
		//printf_s("thread destory\n");
		//destoryHook();
		//destroyEnclave();
		break;
	case DLL_PROCESS_DETACH:
		//printf_s("process destory\n");
		destoryHook();
		destroyEnclave();
		break;
	}
	return TRUE;
}

