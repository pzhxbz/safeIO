#include "stdafx.h"
#include "sgx_process.h"
#include <windows.h>
#include "safeIO_u.h"

#define ENCLAVE_FILE (L"safeIO.signed.dll")

using namespace std;

sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;


int query_sgx_status()
{
	sgx_device_status_t sgx_device_status;
	sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
	if (sgx_ret != SGX_SUCCESS)
	{
		//cout << " Failed to get SGX device status with error number  " << sgx_ret << endl;
		return -1;
	}
	else
	{
		switch (sgx_device_status)
		{
		case SGX_ENABLED:
			//cout << "***** SGX device is enabled ******" << endl;
			return 0;
		case SGX_DISABLED_REBOOT_REQUIRED:
			//printf("SGX device will be enabled after this machine is rebooted.\n");
			return -1;
		case SGX_DISABLED_LEGACY_OS:
			//printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
			return -1;
		case SGX_DISABLED:
			//printf("SGX device not found.\n");
			return -1;
		default:
			//printf("Unexpected error.\n");
			return -1;
		}
	}
}


bool initializeEnclave()
{
	int ret = 0;
	//Sleep(10000);
	printf_s("start init enclave\n");

	if (query_sgx_status() != 0)
	{
		exit(-1);
	}

	if ((ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,
		&enclaveId, NULL)) != SGX_SUCCESS)
	{
		printf("Error %#x: cannot create enclave\n", ret);
		exit(-1);
		return false;
	}

	HANDLE programHandle = unsafe_CreateFile(L"sgxtest.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	if (programHandle == NULL)
	{
		printf("Error : cannot open file\n");
		exit(-1);
		return false;
	}

	size_t programSize = GetFileSize(programHandle, NULL);
	unsigned char* program = (unsigned char*)malloc(programSize);
	DWORD last = 0;
	unsafe_ReadFile(programHandle, program, programSize, &last, NULL);

	unsafe_CloseHandle(programHandle);

	initCheck(enclaveId, (char*)program, programSize);
	free(program);
	return true;
}
bool destroyEnclave()
{
	if (sgx_destroy_enclave(enclaveId) != SGX_SUCCESS)
	{
		printf("Error: cant destroy enclave\n");
		return false;
	}

	return true;
}

void sgx_sendEncrypt(char * src, char * des, size_t len)
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}

	sendEncrypt(enclaveId, src, des, len);
}

void sgx_recvDecrypt(char * src, char * des, size_t len)
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}

	recvDecrypt(enclaveId, src, des, len);

}

void sgx_ReadFileDecrypt(char * src, char * des, size_t len)
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}

	ReadFileDecrypt(enclaveId, src, des, len);

}

void sgx_SendtoEncrypt(char * src, char * des, size_t len)
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}

	SendtoEncrypt(enclaveId, src, des, len);

}

void sgx_recvfromDecrypt(char * src, char * des, size_t len)
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}

	recvDecrypt(enclaveId, src, des, len);
}


int checkInit()
{
	if (enclaveId == 0)
	{
		initializeEnclave();
	}
	return 1;
}