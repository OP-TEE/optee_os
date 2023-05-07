// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <compiler.h>
#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/ts_manager.h>
#include <mm/core_memprot.h>
#include <pta_invoke_tests.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee/cache.h>
#include <trace.h>
#include <types_ext.h>

#include "misc.h"

#define TA_NAME		"invoke_tests.pta"

static TEE_Result test_trace(uint32_t param_types __unused,
			TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	IMSG("pseudo TA \"%s\" says \"Hello world !\"", TA_NAME);

	return TEE_SUCCESS;
}

static int test_v2p2v(void *va, size_t size)
{
	struct ts_session *session = NULL;
	paddr_t p = 0;
	void *v = NULL;

	if  (!va)
		return 0;

	session = ts_get_current_session();
	p = virt_to_phys(va);

	/* 0 is not a valid physical address */
	if (!p)
		return 1;

	if (to_ta_session(session)->clnt_id.login == TEE_LOGIN_TRUSTED_APP) {
		v = phys_to_virt(p, MEM_AREA_TS_VASPACE, size);
	} else {
		v = phys_to_virt(p, MEM_AREA_NSEC_SHM, size);
		if (!v)
			v = phys_to_virt(p, MEM_AREA_SDP_MEM, size);
		if (!v)
			v = phys_to_virt(p, MEM_AREA_SHM_VASPACE, size);
	}

	/*
	 * Return an error only the vaddr found mismatches input address.
	 * Finding a virtual address from a physical address cannot be painful
	 * in some case (i.e pager). Moreover this operation is more debug
	 * related. Thus do not report error if phys_to_virt failed
	 */
	if (v && va != v) {
		EMSG("Failed to p2v/v2p on caller TA memref arguments");
		EMSG("va %p -> pa 0x%" PRIxPA " -> va %p", va, p, v);
		return 1;
	}

	return 0;
}

/*
 * Check PTA can be invoked with a memory reference on a NULL buffer
 */
static TEE_Result test_entry_memref_null(uint32_t type,
					 TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type)
		return TEE_ERROR_BAD_PARAMETERS;

	if (p[0].memref.buffer || p[0].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

/*
 * Supported tests on parameters
 * (I, J, K, L refer to param index)
 *
 * Case 1: command parameters type are: 1 in/out value, 3 empty.
 *         => process outI.a = inI.a + inI.b
 * Case 2: command parameters type are: 3 input value, 1 output value
 *         => process = outI.a = inJ.a + inK.a + inL.a
 * Case 3: command parameters type are: 1 in/out memref, 3 empty.
 *         => process = outI[0] = sum(inI[0..len-1])
 */
static TEE_Result test_entry_params(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	size_t i;
	uint8_t d8, *in;

	/* case 1a: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[0].value.a = p[0].value.a + p[0].value.b;
		return TEE_SUCCESS;
	}
	/* case 1b: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[1].value.a = p[1].value.a + p[1].value.b;
		return TEE_SUCCESS;
	}
	/* case 1c: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		p[2].value.a = p[2].value.a + p[2].value.b;
		return TEE_SUCCESS;
	}
	/* case 1d: 1 input/output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INOUT)) {
		p[3].value.a = p[3].value.a + p[3].value.b;
		return TEE_SUCCESS;
	}

	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[0].value.a = p[1].value.a + p[2].value.a + p[3].value.a;
		p[0].value.b = p[1].value.b + p[2].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[1].value.a = p[0].value.a + p[2].value.a + p[3].value.a;
		p[1].value.b = p[0].value.b + p[2].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_OUTPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_INPUT)) {
		p[2].value.a = p[0].value.a + p[1].value.a + p[3].value.a;
		p[2].value.b = p[0].value.b + p[1].value.b + p[3].value.b;
		return TEE_SUCCESS;
	}
	/* case 2a: 3 input value arguments, 1 output value argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_VALUE_INPUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_VALUE_OUTPUT)) {
		p[3].value.a = p[0].value.a + p[1].value.a + p[2].value.a;
		p[3].value.b = p[0].value.b + p[1].value.b + p[2].value.b;
		return TEE_SUCCESS;
	}

	DMSG("expect memref params: %p/%zu - %p/%zu - %p/%zu - %p/%zu",
	     p[0].memref.buffer, p[0].memref.size, p[1].memref.buffer,
	     p[1].memref.size, p[2].memref.buffer, p[2].memref.size,
	     p[3].memref.buffer, p[3].memref.size);

	/* case 3a: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[0].memref.buffer;
		if (test_v2p2v(in, p[0].memref.size))
			return TEE_ERROR_SECURITY;
		d8 = 0;
		for (i = 0; i < p[0].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[0].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3b: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[1].memref.buffer;
		if (test_v2p2v(in, p[1].memref.size))
			return TEE_ERROR_SECURITY;
		d8 = 0;
		for (i = 0; i < p[1].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[1].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3c: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[2].memref.buffer;
		if (test_v2p2v(in, p[2].memref.size))
			return TEE_ERROR_SECURITY;
		d8 = 0;
		for (i = 0; i < p[2].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[2].memref.buffer = d8;
		return TEE_SUCCESS;
	}
	/* case 3d: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_MEMREF_INOUT)) {
		in = (uint8_t *)p[3].memref.buffer;
		if (test_v2p2v(in, p[3].memref.size))
			return TEE_ERROR_SECURITY;
		d8 = 0;
		for (i = 0; i < p[3].memref.size; i++)
			d8 += in[i];
		*(uint8_t *)p[3].memref.buffer = d8;
		return TEE_SUCCESS;
	}

	EMSG("unexpected parameters");
	return TEE_ERROR_BAD_PARAMETERS;
}

/*
 * Test access to Secure Data Path memory from pseudo TAs
 */

static TEE_Result test_inject_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *src = p[0].memref.buffer;
	char *dst = p[1].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].memref.size < sz) {
		p[1].memref.size = sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!core_vbuf_is(CORE_MEM_NON_SEC, src, sz) ||
	    !core_vbuf_is(CORE_MEM_SDP_MEM, dst, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!sz)
		return TEE_SUCCESS;

	/* Check that core can p2v and v2p over memory reference arguments */
	if (test_v2p2v(src, sz) || test_v2p2v(dst, sz))
		return TEE_ERROR_SECURITY;

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	memcpy(dst, src, sz);

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_transform_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *buf = p[0].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!core_vbuf_is(CORE_MEM_SDP_MEM, buf, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!sz)
		return TEE_SUCCESS;

	/* Check that core can p2v and v2p over memory reference arguments */
	if (test_v2p2v(buf, sz))
		return TEE_ERROR_SECURITY;

	if (cache_operation(TEE_CACHEFLUSH, buf, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	for (; sz; sz--, buf++)
		*buf = ~(*buf) + 1;

	if (cache_operation(TEE_CACHEFLUSH, buf, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result test_dump_sdp(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	char *src = p[0].memref.buffer;
	char *dst = p[1].memref.buffer;
	size_t sz = p[0].memref.size;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != type) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (p[1].memref.size < sz) {
		p[1].memref.size = sz;
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (!core_vbuf_is(CORE_MEM_SDP_MEM, src, sz) ||
	    !core_vbuf_is(CORE_MEM_NON_SEC, dst, sz)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!sz)
		return TEE_SUCCESS;

	/* Check that core can p2v and v2p over memory reference arguments */
	if (test_v2p2v(src, sz) || test_v2p2v(dst, sz))
		return TEE_ERROR_SECURITY;

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	memcpy(dst, src, sz);

	if (cache_operation(TEE_CACHEFLUSH, dst, sz) != TEE_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
	DMSG("create entry point for pseudo TA \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused,
		void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID, uint32_t nParamTypes,
		TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case PTA_INVOKE_TESTS_CMD_TRACE:
		return test_trace(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_PARAMS:
		return test_entry_params(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_MEMREF_NULL:
		return test_entry_memref_null(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_COPY_NSEC_TO_SEC:
		return test_inject_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_READ_MODIFY_SEC:
		return test_transform_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_COPY_SEC_TO_NSEC:
		return test_dump_sdp(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_SELF_TESTS:
		return core_self_tests(nParamTypes, pParams);
#if defined(CFG_REE_FS) && defined(CFG_WITH_USER_TA)
	case PTA_INVOKE_TESTS_CMD_FS_HTREE:
		return core_fs_htree_tests(nParamTypes, pParams);
#endif
	case PTA_INVOKE_TESTS_CMD_MUTEX:
		return core_mutex_tests(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_LOCKDEP:
		return core_lockdep_tests(nParamTypes, pParams);
	case PTA_INVOKE_TEST_CMD_AES_PERF:
		return core_aes_perf_tests(nParamTypes, pParams);
	case PTA_INVOKE_TESTS_CMD_DT_DRIVER_TESTS:
		return core_dt_driver_tests(nParamTypes, pParams);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_INVOKE_TESTS_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SECURE_DATA_PATH |
			    TA_FLAG_CONCURRENT | TA_FLAG_DEVICE_ENUM,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
