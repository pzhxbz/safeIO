// sgxtest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "safeIO_u.h"

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include "sgx_urts.h"
#include "sgx_capable.h"
#define ENCLAVE_FILE (L"safeIO.signed.dll")

using namespace std;

sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;

char test[] = "qwerqwrqwerqwerqwer";

bool initializeEnclave()
{
	int ret = 0;
	//Sleep(10000);
	printf_s("start init enclave\n");

	if ((ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,
		&enclaveId, NULL)) != SGX_SUCCESS)
	{
		printf("Error %#x: cannot create enclave\n", ret);

		exit(-1);
		return false;
	}

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

int main()
{
	initializeEnclave();

	initCheck(enclaveId, test, strlen(test));
	//cpp_int_test(enclaveId);
	destroyEnclave();
	return 0;
}

