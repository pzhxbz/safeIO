#ifndef SAFEIO_T_H__
#define SAFEIO_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgxssl_texception.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void sendEncrypt(char* src, char* des, size_t len);
void recvDecrypt(char* src, char* des, size_t len);
void ReadFileDecrypt(char* src, char* des, size_t len);
void SendtoEncrypt(char* src, char* des, size_t len);
void recvfromDecrypt(char* src, char* des, size_t len);
void initCheck(char* src, size_t len, int* results);
void cpp_int_test();

sgx_status_t SGX_CDECL unsafe_send(int* retval, int s, char* buf, int len, int flags);
sgx_status_t SGX_CDECL unsafe_recv(int* retval, int s, char* buf, int len, int flags);
sgx_status_t SGX_CDECL unsafe_initSocket(int* retval, int* socket, char* ip, int port);
sgx_status_t SGX_CDECL unsafe_closesocket(int* retval, int s);
sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
