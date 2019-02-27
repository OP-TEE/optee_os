// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <compiler.h>
#include <kernel/pseudo_ta.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <pta_invoke_tests.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

#include "core_self_tests.h"

#define TA_NAME		"invoke_tests.pta"

static TEE_Result test_trace(uint32_t param_types __unused,
			TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	IMSG("pseudo TA \"%s\" says \"Hello world !\"", TA_NAME);

	return TEE_SUCCESS;
}

static int test_v2p2v(void *va)
{
	struct tee_ta_session *session;
	paddr_t p;
	void *v;

	if  (!va)
		return 0;

	if (tee_ta_get_current_session(&session))
		panic();

	p = virt_to_phys(va);

	/* 0 is not a valid physical address */
	if (!p)
		return 1;

	if (session->clnt_id.login == TEE_LOGIN_TRUSTED_APP) {
		v = phys_to_virt(p, MEM_AREA_TA_VASPACE);
	} else {
		v = phys_to_virt(p, MEM_AREA_NSEC_SHM);
		if (!v)
			v = phys_to_virt(p, MEM_AREA_SDP_MEM);
		if (!v)
			v = phys_to_virt(p, MEM_AREA_SHM_VASPACE);
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

	DMSG("expect memref params: %p/%" PRIu32 " - %p/%" PRIu32 "zu - %p/%" PRIu32 "zu - %p/%" PRIu32 "zu",
			p[0].memref.buffer, p[0].memref.size,
			p[1].memref.buffer, p[1].memref.size,
			p[2].memref.buffer, p[2].memref.size,
			p[3].memref.buffer, p[3].memref.size);

	/* case 3a: 1 in/out memref argument */
	if ((TEE_PARAM_TYPE_GET(type, 0) == TEE_PARAM_TYPE_MEMREF_INOUT) &&
		(TEE_PARAM_TYPE_GET(type, 1) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 2) == TEE_PARAM_TYPE_NONE) &&
		(TEE_PARAM_TYPE_GET(type, 3) == TEE_PARAM_TYPE_NONE)) {
		in = (uint8_t *)p[0].memref.buffer;
		if (test_v2p2v(in))
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
		if (test_v2p2v(in))
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
		if (test_v2p2v(in))
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
		if (test_v2p2v(in))
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
	if (test_v2p2v(src) || test_v2p2v(src + sz - 1) ||
	    test_v2p2v(dst) || test_v2p2v(dst + sz - 1))
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
	if (test_v2p2v(buf) || test_v2p2v(buf + sz - 1))
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
	if (test_v2p2v(src) || test_v2p2v(src + sz - 1) ||
	    test_v2p2v(dst) || test_v2p2v(dst + sz - 1))
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

static TEE_Result open_session(uint32_t param_type __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **session __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *session __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *session __unused,
				 uint32_t command_id, uint32_t params_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo ta \"%s\"", TA_NAME);

	switch (command_id) {
	case PTA_INVOKE_TESTS_CMD_TRACE:
		return test_trace(params_types, params);
	case PTA_INVOKE_TESTS_CMD_PARAMS:
		return test_entry_params(params_types, params);
	case PTA_INVOKE_TESTS_CMD_COPY_NSEC_TO_SEC:
		return test_inject_sdp(params_types, params);
	case PTA_INVOKE_TESTS_CMD_READ_MODIFY_SEC:
		return test_transform_sdp(params_types, params);
	case PTA_INVOKE_TESTS_CMD_COPY_SEC_TO_NSEC:
		return test_dump_sdp(params_types, params);
	case PTA_INVOKE_TESTS_CMD_SELF_TESTS:
		return core_self_tests(params_types, params);
#if defined(CFG_WITH_USER_TA)
	case PTA_INVOKE_TESTS_CMD_FS_HTREE:
		return core_fs_htree_tests(params_types, params);
#endif
	case PTA_INVOKE_TESTS_CMD_MUTEX:
		return core_mutex_tests(params_types, params);
	case PTA_INVOKE_TESTS_CMD_LOCKDEP:
		return core_lockdep_tests(params_types, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_INVOKE_TESTS_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SECURE_DATA_PATH |
			    TA_FLAG_CONCURRENT,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
