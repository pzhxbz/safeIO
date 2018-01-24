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
	void * func_addr[5];
} ocall_table_safeIO = {
	5,
	{
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

