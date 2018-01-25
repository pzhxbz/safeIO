#pragma once


#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include <iostream>

int query_sgx_status();

bool initializeEnclave();
bool destroyEnclave();


void sgx_sendEncrypt(char* src, char* des, size_t len);
void sgx_recvDecrypt(char* src, char* des, size_t len);
void sgx_ReadFileDecrypt(char* src, char* des, size_t len);
void sgx_SendtoEncrypt(char* src, char* des, size_t len);
void sgx_recvfromDecrypt(char* src, char* des, size_t len);