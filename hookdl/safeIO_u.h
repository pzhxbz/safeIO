#ifndef SAFEIO_U_H__
#define SAFEIO_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, unsafe_send, (int s, char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, unsafe_recv, (int s, char* buf, int len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, unsafe_initSocket, (int* socket, char* ip, int port));
int SGX_UBRIDGE(SGX_NOCONVENTION, unsafe_closesocket, (int s));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime64, (void* timeptr, uint32_t timeb64Len));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t sendEncrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len);
sgx_status_t recvDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len);
sgx_status_t ReadFileDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len);
sgx_status_t SendtoEncrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len);
sgx_status_t recvfromDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len);
sgx_status_t initCheck(sgx_enclave_id_t eid, char* src, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
