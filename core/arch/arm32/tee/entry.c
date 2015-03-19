/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee/entry.h>
#include <sm/teesmc.h>
#include <kernel/tee_common_unpg.h>
#include <kernel/tee_dispatch.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>

#include <assert.h>

#define SHM_CACHE_ATTRS	\
	(core_mmu_is_shm_cached() ? \
		(TEESMC_ATTR_CACHE_DEFAULT << TEESMC_ATTR_CACHE_SHIFT) : 0 )

static bool copy_in_params(const struct teesmc32_param *params,
		uint32_t num_params, uint32_t *param_types,
		uint32_t param_attr[TEE_NUM_PARAMS],
		TEE_Param tee_params[TEE_NUM_PARAMS])
{
	size_t n;
	uint8_t pt[4];

	*param_types = 0;

	if (num_params > TEE_NUM_PARAMS)
		return false;

	for (n = 0; n < num_params; n++) {
		if (params[n].attr & TEESMC_ATTR_META)
			return false;

		pt[n] = params[n].attr & TEESMC_ATTR_TYPE_MASK;

		param_attr[n] = (params[n].attr >> TEESMC_ATTR_CACHE_SHIFT) &
				TEESMC_ATTR_CACHE_MASK;

		if ((params[n].attr & TEESMC_ATTR_TYPE_MASK) ==
		    TEESMC_ATTR_TYPE_NONE) {
			tee_params[n].value.a = 0;
			tee_params[n].value.b = 0;
		} else {
			tee_params[n].value.a = params[n].u.value.a;
			tee_params[n].value.b = params[n].u.value.b;
		}
	}
	for (; n < TEE_NUM_PARAMS; n++) {
		pt[n] = TEE_PARAM_TYPE_NONE;
		param_attr[n] = 0;
		tee_params[n].value.a = 0;
		tee_params[n].value.b = 0;
	}

	*param_types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return true;
}

static void copy_out_param(const TEE_Param tee_params[TEE_NUM_PARAMS],
		uint32_t param_types, uint32_t num_params,
		struct teesmc32_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].u.memref.size = tee_params[n].memref.size;
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = tee_params[n].value.a;
			params[n].u.value.b = tee_params[n].value.b;
			break;
		default:
			break;
		}
	}
}

/*
 * Extracts mandatory parameter for open session.
 *
 * Returns
 * false : mandatory parameter wasn't found or malformatted
 * true  : paramater found and OK
 */
static bool get_open_session_meta(struct teesmc32_arg *arg32,
		uint32_t num_params, size_t *num_meta,
		struct teesmc_meta_open_session **meta)
{
	struct teesmc32_param *params = TEESMC32_GET_PARAMS(arg32);
	uint32_t phmeta;
	const uint8_t req_attr = TEESMC_ATTR_META |
				 TEESMC_ATTR_TYPE_MEMREF_INPUT |
				 SHM_CACHE_ATTRS;

	if (num_params < (*num_meta + 1))
		return false;

	if (params[*num_meta].attr != req_attr)
		return false;

	if (params[*num_meta].u.memref.size !=
			sizeof(struct teesmc_meta_open_session))
		return false;

	phmeta = params[*num_meta].u.memref.buf_ptr;
	if (!tee_pbuf_is_non_sec(phmeta,
				 sizeof(struct teesmc_meta_open_session)))
		return false;

	if (core_pa2va(phmeta, meta))
		return false;

	(*num_meta)++;
	return true;
}

/*
 * Extracts optional pointer to a Trusted Application.
 *
 * Returns
 * false : malformatted TA parameter
 * true  : if TA parameter wasn't found or if it was found and OK
 */
static bool get_open_session_ta(struct teesmc32_arg *arg32, size_t num_params,
		size_t *num_meta, kta_signed_header_t **ta)
{
	struct teesmc32_param *params = TEESMC32_GET_PARAMS(arg32);
	uint32_t ph;
	size_t len;
	const uint8_t req_attr = TEESMC_ATTR_META |
				 TEESMC_ATTR_TYPE_MEMREF_INPUT |
				 SHM_CACHE_ATTRS;

	if (num_params < (*num_meta + 1))
		return false;

	if (!(params[*num_meta].attr & TEESMC_ATTR_META))
		return true;

	if (params[*num_meta].attr != req_attr)
		return false;

	ph = params[*num_meta].u.memref.buf_ptr;
	if (params[*num_meta].u.memref.size < sizeof(kta_signed_header_t))
		return false;

	if (!tee_pbuf_is_non_sec(ph, sizeof(kta_signed_header_t)))
		return false;

	if (core_pa2va(ph, ta))
		return false;

	len = (*ta)->size_of_signed_header + (*ta)->size_of_payload;
	if (params[*num_meta].u.memref.size < len)
		return false;

	if (!tee_pbuf_is_non_sec(ph, len))
		return false;

	(*num_meta)++;
	return true;
}

static void entry_open_session(struct thread_smc_args *args,
			struct teesmc32_arg *arg32, uint32_t num_params)
{
	struct tee_dispatch_open_session_in in;
	struct tee_dispatch_open_session_out out;
	struct teesmc_meta_open_session *meta;
	struct teesmc32_param *params = TEESMC32_GET_PARAMS(arg32);
	size_t num_meta = 0;

	if (!get_open_session_meta(arg32, num_params, &num_meta, &meta))
		goto bad_params;

	in.ta = NULL;
	if (!get_open_session_ta(arg32, num_params, &num_meta, &in.ta))
		goto bad_params;

	COMPILE_TIME_ASSERT(sizeof(TEE_UUID) == TEESMC_UUID_LEN);
	memcpy(&in.uuid, &meta->uuid, sizeof(TEE_UUID));
	memcpy(&in.clnt_id.uuid, &meta->clnt_uuid, sizeof(TEE_UUID));
	in.clnt_id.login = meta->clnt_login;

	if (!copy_in_params(params + num_meta, num_params - num_meta,
			    &in.param_types, in.param_attr, in.params))
		goto bad_params;

	(void)tee_dispatch_open_session(&in, &out);
	if (out.msg.res == TEE_ERROR_SYSTEM_BUSY) {
		args->a0 = TEESMC_RETURN_EBUSY;
		return;
	}

	copy_out_param(out.params, in.param_types, num_params - num_meta,
		       params + num_meta);

	arg32->session = (vaddr_t)out.sess;
	arg32->ret = out.msg.res;
	arg32->ret_origin = out.msg.err;
	args->a0 = TEESMC_RETURN_OK;
	return;

bad_params:
	DMSG("Bad params");
	arg32->ret = TEE_ERROR_BAD_PARAMETERS;
	arg32->ret_origin = TEE_ORIGIN_TEE;
	args->a0 = TEESMC_RETURN_OK;
}

static void entry_close_session(struct thread_smc_args *args,
			struct teesmc32_arg *arg32, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_close_session_in in;
		uint32_t ret;

		in.sess = arg32->session;
		ret = tee_dispatch_close_session(&in);
		if (ret == TEE_ERROR_SYSTEM_BUSY) {
			args->a0 = TEESMC_RETURN_EBUSY;
			return;
		}
		arg32->ret = ret;
	} else {
		arg32->ret = TEE_ERROR_BAD_PARAMETERS;
	}

	arg32->ret_origin = TEE_ORIGIN_TEE;
	args->a0 = TEESMC_RETURN_OK;
}

static void entry_invoke_command(struct thread_smc_args *args,
			struct teesmc32_arg *arg32, uint32_t num_params)
{
	struct tee_dispatch_invoke_command_in in;
	struct tee_dispatch_invoke_command_out out;
	struct teesmc32_param *params = TEESMC32_GET_PARAMS(arg32);

	if (!copy_in_params(params, num_params,
			 &in.param_types, in.param_attr, in.params)) {
		arg32->ret = TEE_ERROR_BAD_PARAMETERS;
		arg32->ret_origin = TEE_ORIGIN_TEE;
		args->a0 = TEESMC_RETURN_OK;
		return;
	}

	in.sess = (TEE_Session *)(vaddr_t)arg32->session;
	in.cmd = arg32->ta_func;
	(void)tee_dispatch_invoke_command(&in, &out);
	if (out.msg.res == TEE_ERROR_SYSTEM_BUSY) {
		args->a0 = TEESMC_RETURN_EBUSY;
		return;
	}

	copy_out_param(out.params, in.param_types, num_params, params);

	arg32->ret = out.msg.res;
	arg32->ret_origin = out.msg.err;
	args->a0 = TEESMC_RETURN_OK;
}

static void entry_cancel(struct thread_smc_args *args,
			struct teesmc32_arg *arg32, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_dispatch_cancel_command_in in;
		struct tee_dispatch_cancel_command_out out;

		in.sess = (TEE_Session *)(vaddr_t)arg32->session;
		(void)tee_dispatch_cancel_command(&in, &out);

		if (out.msg.res == TEE_ERROR_SYSTEM_BUSY) {
			args->a0 = TEESMC_RETURN_EBUSY;
			return;
		}

		arg32->ret = out.msg.res;
		arg32->ret_origin = out.msg.err;
	} else {
		arg32->ret = TEE_ERROR_BAD_PARAMETERS;
		arg32->ret_origin = TEE_ORIGIN_TEE;
	}

	args->a0 = TEESMC_RETURN_OK;
}



static void tee_entry_call_with_arg(struct thread_smc_args *args)
{
	struct teesmc32_arg *arg32 = NULL;	/* fix gcc warning */
	uint32_t num_params;

	if (args->a0 != TEESMC32_CALL_WITH_ARG &&
	    args->a0 != TEESMC32_FASTCALL_WITH_ARG) {
		EMSG("Unknown SMC 0x%x\n", args->a0);
		DMSG("Expected 0x%x or 0x%x\n",
		     TEESMC32_CALL_WITH_ARG, TEESMC32_FASTCALL_WITH_ARG);
		args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
		return;
	}

	if (args->a0 == TEESMC32_CALL_WITH_ARG)
		thread_set_irq(true);	/* Enable IRQ for STD calls */

	if (!tee_pbuf_is_non_sec(args->a1, sizeof(struct teesmc32_arg)) ||
	    !TEE_ALIGNMENT_IS_OK(args->a1, struct teesmc32_arg) ||
	    core_pa2va(args->a1, &arg32)) {
		EMSG("Bad arg address 0x%x\n", args->a1);
		args->a0 = TEESMC_RETURN_EBADADDR;
		return;
	}

	num_params = arg32->num_params;
	if (!tee_pbuf_is_non_sec(args->a1, TEESMC32_GET_ARG_SIZE(num_params))) {
		EMSG("Bad arg address 0x%x\n", args->a1);
		args->a0 = TEESMC_RETURN_EBADADDR;
		return;
	}

	if (args->a0 == TEESMC32_CALL_WITH_ARG) {
		switch (arg32->cmd) {
		case TEESMC_CMD_OPEN_SESSION:
			entry_open_session(args, arg32, num_params);
			break;
		case TEESMC_CMD_CLOSE_SESSION:
			entry_close_session(args, arg32, num_params);
			break;
		case TEESMC_CMD_INVOKE_COMMAND:
			entry_invoke_command(args, arg32, num_params);
			break;
		case TEESMC_CMD_CANCEL:
			entry_cancel(args, arg32, num_params);
			break;
		default:
			EMSG("Unknown cmd 0x%x\n", arg32->cmd);
			args->a0 = TEESMC_RETURN_EBADCMD;
		}
	} else {
		EMSG("Unknown fastcall cmd 0x%x\n", arg32->cmd);
		args->a0 = TEESMC_RETURN_EBADCMD;
	}
}

void tee_entry(struct thread_smc_args *args)
{
	switch (args->a0) {
	case TEESMC32_CALLS_COUNT:
		tee_entry_get_api_call_count(args);
		break;
	case TEESMC32_CALLS_UID:
		tee_entry_get_api_uuid(args);
		break;
	case TEESMC32_CALLS_REVISION:
		tee_entry_get_api_revision(args);
		break;
	case TEESMC32_CALL_GET_OS_UUID:
		tee_entry_get_os_uuid(args);
		break;
	case TEESMC32_CALL_GET_OS_REVISION:
		tee_entry_get_os_revision(args);
		break;
	case TEESMC32_CALL_WITH_ARG:
	case TEESMC64_CALL_WITH_ARG:
		tee_entry_call_with_arg(args);
		break;
	default:
		args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}

size_t tee_entry_generic_get_api_call_count(void)
{
	/*
	 * All the differnt calls handled in this file. If the specific
	 * target has additional calls it will call this function and
	 * add the number of calls the target has added.
	 */
	return 7;
}

void __attribute__((weak)) tee_entry_get_api_call_count(
		struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count();
}

void __attribute__((weak)) tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = TEESMC_UID_R0;
	args->a1 = TEESMC_UID_R1;
	args->a2 = TEESMC_UID_R2;
	args->a3 = TEESMC_UID32_R3;
}

void __attribute__((weak)) tee_entry_get_api_revision(
		struct thread_smc_args *args)
{
	args->a0 = TEESMC_REVISION_MAJOR;
	args->a1 = TEESMC_REVISION_MINOR;
}

void __attribute__((weak)) tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	/* Not implemented */
	args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
}

void __attribute__((weak)) tee_entry_get_os_revision(
		struct thread_smc_args *args)
{
	/* Not implemented */
	args->a0 = TEESMC_RETURN_UNKNOWN_FUNCTION;
}
