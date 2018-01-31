#include "safeIO_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_sendEncrypt(void* pms)
{
	ms_sendEncrypt_t* ms = SGX_CAST(ms_sendEncrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;
	char* _tmp_des = ms->ms_des;

	CHECK_REF_POINTER(pms, sizeof(ms_sendEncrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	sendEncrypt(_in_src, _tmp_des, _tmp_len);
err:
	if (_in_src) free(_in_src);

	return status;
}

static sgx_status_t SGX_CDECL sgx_recvDecrypt(void* pms)
{
	ms_recvDecrypt_t* ms = SGX_CAST(ms_recvDecrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;
	char* _tmp_des = ms->ms_des;
	size_t _len_des = _tmp_len;
	char* _in_des = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_recvDecrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);
	CHECK_UNIQUE_POINTER(_tmp_des, _len_des);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	if (_tmp_des != NULL) {
		if ((_in_des = (char*)malloc(_len_des)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_des, 0, _len_des);
	}
	recvDecrypt(_in_src, _in_des, _tmp_len);
err:
	if (_in_src) free(_in_src);
	if (_in_des) {
		memcpy(_tmp_des, _in_des, _len_des);
		free(_in_des);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ReadFileDecrypt(void* pms)
{
	ms_ReadFileDecrypt_t* ms = SGX_CAST(ms_ReadFileDecrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;
	char* _tmp_des = ms->ms_des;

	CHECK_REF_POINTER(pms, sizeof(ms_ReadFileDecrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	ReadFileDecrypt(_in_src, _tmp_des, _tmp_len);
err:
	if (_in_src) free(_in_src);

	return status;
}

static sgx_status_t SGX_CDECL sgx_SendtoEncrypt(void* pms)
{
	ms_SendtoEncrypt_t* ms = SGX_CAST(ms_SendtoEncrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;
	char* _tmp_des = ms->ms_des;
	size_t _len_des = _tmp_len;
	char* _in_des = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_SendtoEncrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);
	CHECK_UNIQUE_POINTER(_tmp_des, _len_des);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	if (_tmp_des != NULL) {
		if ((_in_des = (char*)malloc(_len_des)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_des, 0, _len_des);
	}
	SendtoEncrypt(_in_src, _in_des, _tmp_len);
err:
	if (_in_src) free(_in_src);
	if (_in_des) {
		memcpy(_tmp_des, _in_des, _len_des);
		free(_in_des);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_recvfromDecrypt(void* pms)
{
	ms_recvfromDecrypt_t* ms = SGX_CAST(ms_recvfromDecrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;
	char* _tmp_des = ms->ms_des;
	size_t _len_des = _tmp_len;
	char* _in_des = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_recvfromDecrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);
	CHECK_UNIQUE_POINTER(_tmp_des, _len_des);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	if (_tmp_des != NULL) {
		if ((_in_des = (char*)malloc(_len_des)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_des, 0, _len_des);
	}
	recvfromDecrypt(_in_src, _in_des, _tmp_len);
err:
	if (_in_src) free(_in_src);
	if (_in_des) {
		memcpy(_tmp_des, _in_des, _len_des);
		free(_in_des);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_initCheck(void* pms)
{
	ms_initCheck_t* ms = SGX_CAST(ms_initCheck_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_src = ms->ms_src;
	size_t _tmp_len = ms->ms_len;
	size_t _len_src = _tmp_len;
	char* _in_src = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_initCheck_t));
	CHECK_UNIQUE_POINTER(_tmp_src, _len_src);

	if (_tmp_src != NULL) {
		_in_src = (char*)malloc(_len_src);
		if (_in_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_src, _tmp_src, _len_src);
	}
	initCheck(_in_src, _tmp_len);
err:
	if (_in_src) free(_in_src);

	return status;
}

static sgx_status_t SGX_CDECL sgx_cpp_int_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	cpp_int_test();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_sendEncrypt, 0},
		{(void*)(uintptr_t)sgx_recvDecrypt, 0},
		{(void*)(uintptr_t)sgx_ReadFileDecrypt, 0},
		{(void*)(uintptr_t)sgx_SendtoEncrypt, 0},
		{(void*)(uintptr_t)sgx_recvfromDecrypt, 0},
		{(void*)(uintptr_t)sgx_initCheck, 0},
		{(void*)(uintptr_t)sgx_cpp_int_test, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][7];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL unsafe_send(int* retval, int s, char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_unsafe_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_unsafe_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_unsafe_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_unsafe_send_t));

	ms->ms_s = s;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy(ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL unsafe_recv(int* retval, int s, char* buf, int len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_unsafe_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_unsafe_recv_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_unsafe_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_unsafe_recv_t));

	ms->ms_s = s;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL unsafe_initSocket(int* retval, int* socket, char* ip, int port)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_socket = sizeof(*socket);
	size_t _len_ip = ip ? strlen(ip) + 1 : 0;

	ms_unsafe_initSocket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_unsafe_initSocket_t);
	void *__tmp = NULL;

	ocalloc_size += (socket != NULL && sgx_is_within_enclave(socket, _len_socket)) ? _len_socket : 0;
	ocalloc_size += (ip != NULL && sgx_is_within_enclave(ip, _len_ip)) ? _len_ip : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_unsafe_initSocket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_unsafe_initSocket_t));

	if (socket != NULL && sgx_is_within_enclave(socket, _len_socket)) {
		ms->ms_socket = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_socket);
		memset(ms->ms_socket, 0, _len_socket);
	} else if (socket == NULL) {
		ms->ms_socket = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (ip != NULL && sgx_is_within_enclave(ip, _len_ip)) {
		ms->ms_ip = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ip);
		memcpy(ms->ms_ip, ip, _len_ip);
	} else if (ip == NULL) {
		ms->ms_ip = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port = port;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (socket) memcpy((void*)socket, ms->ms_socket, _len_socket);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL unsafe_closesocket(int* retval, int s)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_unsafe_closesocket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_unsafe_closesocket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_unsafe_closesocket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_unsafe_closesocket_t));

	ms->ms_s = s;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb64Len;

	ms_u_sgxssl_ftime64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime64_t);
	void *__tmp = NULL;

	ocalloc_size += (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) ? _len_timeptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime64_t));

	if (timeptr != NULL && sgx_is_within_enclave(timeptr, _len_timeptr)) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		memset(ms->ms_timeptr, 0, _len_timeptr);
	} else if (timeptr == NULL) {
		ms->ms_timeptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_timeb64Len = timeb64Len;
	status = sgx_ocall(4, ms);

	if (timeptr) memcpy((void*)timeptr, ms->ms_timeptr, _len_timeptr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
