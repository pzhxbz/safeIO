#include "safeIO_u.h"
#include <errno.h>

typedef struct ms_sendEncrypt_t {
	char* ms_src;
	char* ms_des;
	size_t ms_len;
} ms_sendEncrypt_t;

typedef struct ms_recvDecrypt_t {
	char* ms_src;
	char* ms_des;
	size_t ms_len;
} ms_recvDecrypt_t;

typedef struct ms_ReadFileDecrypt_t {
	char* ms_src;
	char* ms_des;
	size_t ms_len;
} ms_ReadFileDecrypt_t;

typedef struct ms_SendtoEncrypt_t {
	char* ms_src;
	char* ms_des;
	size_t ms_len;
} ms_SendtoEncrypt_t;

typedef struct ms_recvfromDecrypt_t {
	char* ms_src;
	char* ms_des;
	size_t ms_len;
} ms_recvfromDecrypt_t;

typedef struct ms_initCheck_t {
	char* ms_src;
	size_t ms_len;
	int* ms_results;
} ms_initCheck_t;


typedef struct ms_unsafe_send_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_unsafe_send_t;

typedef struct ms_unsafe_recv_t {
	int ms_retval;
	int ms_s;
	char* ms_buf;
	int ms_len;
	int ms_flags;
} ms_unsafe_recv_t;

typedef struct ms_unsafe_initSocket_t {
	int ms_retval;
	int* ms_socket;
	char* ms_ip;
	int ms_port;
} ms_unsafe_initSocket_t;

typedef struct ms_unsafe_closesocket_t {
	int ms_retval;
	int ms_s;
} ms_unsafe_closesocket_t;

typedef struct ms_u_sgxssl_ftime64_t {
	void* ms_timeptr;
	uint32_t ms_timeb64Len;
} ms_u_sgxssl_ftime64_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL safeIO_unsafe_send(void* pms)
{
	ms_unsafe_send_t* ms = SGX_CAST(ms_unsafe_send_t*, pms);
	ms->ms_retval = unsafe_send(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_unsafe_recv(void* pms)
{
	ms_unsafe_recv_t* ms = SGX_CAST(ms_unsafe_recv_t*, pms);
	ms->ms_retval = unsafe_recv(ms->ms_s, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_unsafe_initSocket(void* pms)
{
	ms_unsafe_initSocket_t* ms = SGX_CAST(ms_unsafe_initSocket_t*, pms);
	ms->ms_retval = unsafe_initSocket(ms->ms_socket, ms->ms_ip, ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_unsafe_closesocket(void* pms)
{
	ms_unsafe_closesocket_t* ms = SGX_CAST(ms_unsafe_closesocket_t*, pms);
	ms->ms_retval = unsafe_closesocket(ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_u_sgxssl_ftime64(void* pms)
{
	ms_u_sgxssl_ftime64_t* ms = SGX_CAST(ms_u_sgxssl_ftime64_t*, pms);
	u_sgxssl_ftime64(ms->ms_timeptr, ms->ms_timeb64Len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL safeIO_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[10];
} ocall_table_safeIO = {
	10,
	{
		(void*)(uintptr_t)safeIO_unsafe_send,
		(void*)(uintptr_t)safeIO_unsafe_recv,
		(void*)(uintptr_t)safeIO_unsafe_initSocket,
		(void*)(uintptr_t)safeIO_unsafe_closesocket,
		(void*)(uintptr_t)safeIO_u_sgxssl_ftime64,
		(void*)(uintptr_t)safeIO_sgx_oc_cpuidex,
		(void*)(uintptr_t)safeIO_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)safeIO_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)safeIO_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)safeIO_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t sendEncrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len)
{
	sgx_status_t status;
	ms_sendEncrypt_t ms;
	ms.ms_src = src;
	ms.ms_des = des;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t recvDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len)
{
	sgx_status_t status;
	ms_recvDecrypt_t ms;
	ms.ms_src = src;
	ms.ms_des = des;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t ReadFileDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len)
{
	sgx_status_t status;
	ms_ReadFileDecrypt_t ms;
	ms.ms_src = src;
	ms.ms_des = des;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t SendtoEncrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len)
{
	sgx_status_t status;
	ms_SendtoEncrypt_t ms;
	ms.ms_src = src;
	ms.ms_des = des;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t recvfromDecrypt(sgx_enclave_id_t eid, char* src, char* des, size_t len)
{
	sgx_status_t status;
	ms_recvfromDecrypt_t ms;
	ms.ms_src = src;
	ms.ms_des = des;
	ms.ms_len = len;
	status = sgx_ecall(eid, 4, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t initCheck(sgx_enclave_id_t eid, char* src, size_t len, int* results)
{
	sgx_status_t status;
	ms_initCheck_t ms;
	ms.ms_src = src;
	ms.ms_len = len;
	ms.ms_results = results;
	status = sgx_ecall(eid, 5, &ocall_table_safeIO, &ms);
	return status;
}

sgx_status_t cpp_int_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_safeIO, NULL);
	return status;
}

