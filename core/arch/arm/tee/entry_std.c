/*
 * Copyright (c) 2015-2016, Linaro Limited
 * All rights reserved.
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
#include <assert.h>
#include <compiler.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/tee_dispatch.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <string.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/uuid.h>
#include <util.h>

#define SHM_CACHE_ATTRS	\
	(uint32_t)(core_mmu_is_shm_cached() ?  OPTEE_SMC_SHM_CACHED : 0)

static struct mobj *shm_mobj;

static bool set_mem_param(const struct optee_msg_param *param,
			  struct param_mem *mem)
{
	paddr_t b;
	size_t sz;
	size_t tsz;

	if (mobj_get_pa(shm_mobj, 0, 0, &b) != TEE_SUCCESS)
		panic("Failed to be PA of shared memory MOBJ");

	sz = shm_mobj->size;
	tsz = param->u.tmem.size;
	if (param->u.tmem.buf_ptr && !tsz)
		tsz++;
	if (!core_is_buffer_inside(param->u.tmem.buf_ptr, tsz, b, sz))
		return false;

	mem->mobj = shm_mobj;
	mem->offs = param->u.tmem.buf_ptr - b;
	mem->size = param->u.tmem.size;
	return true;
}

static bool copy_in_params(const struct optee_msg_param *params,
		uint32_t num_params, struct tee_ta_param *ta_param)
{
	size_t n;
	uint8_t pt[TEE_NUM_PARAMS];

	if (num_params > TEE_NUM_PARAMS)
		return false;

	memset(ta_param, 0, sizeof(*ta_param));

	for (n = 0; n < num_params; n++) {
		uint32_t attr;

		if (params[n].attr & OPTEE_MSG_ATTR_META)
			return false;
		if (params[n].attr & OPTEE_MSG_ATTR_FRAGMENT)
			return false;

		attr = params[n].attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			pt[n] = TEE_PARAM_TYPE_NONE;
			memset(&ta_param->u[n], 0, sizeof(ta_param->u[n]));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			pt[n] = TEE_PARAM_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			ta_param->u[n].val.a = params[n].u.value.a;
			ta_param->u[n].val.b = params[n].u.value.b;
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			pt[n] = TEE_PARAM_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			if (!set_mem_param(params + n, &ta_param->u[n].mem))
				return false;
			break;
		default:
			return false;
		}
	}

	ta_param->types = TEE_PARAM_TYPES(pt[0], pt[1], pt[2], pt[3]);

	return true;
}

static void copy_out_param(struct tee_ta_param *ta_param, uint32_t num_params,
			   struct optee_msg_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		switch (TEE_PARAM_TYPE_GET(ta_param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].u.tmem.size = ta_param->u[n].mem.size;
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = ta_param->u[n].val.a;
			params[n].u.value.b = ta_param->u[n].val.b;
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
static bool get_open_session_meta(struct optee_msg_arg *arg,
		uint32_t num_params, size_t *num_meta,
		TEE_UUID *uuid, TEE_Identity *clnt_id)
{
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	const uint32_t req_attr = OPTEE_MSG_ATTR_META |
				  OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;

	if (num_params < (*num_meta + 2))
		return false;

	if (params[*num_meta].attr != req_attr ||
	    params[*num_meta + 1].attr != req_attr)
		return false;

	tee_uuid_from_octets(uuid, (void *)&params[*num_meta].u.value);
	tee_uuid_from_octets(&clnt_id->uuid,
			     (void *)&params[*num_meta + 1].u.value);
	clnt_id->login = params[*num_meta + 1].u.value.c;

	(*num_meta) += 2;
	return true;
}

static void entry_open_session(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	struct tee_dispatch_open_session_in in;
	struct tee_dispatch_open_session_out out;
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);
	size_t num_meta = 0;

	if (!get_open_session_meta(arg, num_params, &num_meta, &in.uuid,
				   &in.clnt_id))
		goto bad_params;

	if (!copy_in_params(params + num_meta, num_params - num_meta,
			    &in.param))
		goto bad_params;

	(void)tee_dispatch_open_session(&in, &out);

	copy_out_param(&out.param, num_params - num_meta, params + num_meta);

	arg->session = (vaddr_t)out.sess;
	arg->ret = out.msg.res;
	arg->ret_origin = out.msg.err;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
	return;

bad_params:
	DMSG("Bad params");
	arg->ret = TEE_ERROR_BAD_PARAMETERS;
	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_close_session(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_close_session_in in;

		in.sess = (TEE_Session *)(uintptr_t)arg->session;
		arg->ret = tee_dispatch_close_session(&in);
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
	}

	arg->ret_origin = TEE_ORIGIN_TEE;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_invoke_command(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{
	struct tee_dispatch_invoke_command_in in;
	struct tee_dispatch_invoke_command_out out;
	struct optee_msg_param *params = OPTEE_MSG_GET_PARAMS(arg);

	if (!copy_in_params(params, num_params, &in.param)) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
		smc_args->a0 = OPTEE_SMC_RETURN_OK;
		return;
	}

	in.sess = (TEE_Session *)(vaddr_t)arg->session;
	in.cmd = arg->func;
	(void)tee_dispatch_invoke_command(&in, &out);

	copy_out_param(&out.param, num_params, params);

	arg->ret = out.msg.res;
	arg->ret_origin = out.msg.err;
	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

static void entry_cancel(struct thread_smc_args *smc_args,
			struct optee_msg_arg *arg, uint32_t num_params)
{

	if (num_params == 0) {
		struct tee_dispatch_cancel_command_in in;
		struct tee_dispatch_cancel_command_out out;

		in.sess = (TEE_Session *)(vaddr_t)arg->session;
		(void)tee_dispatch_cancel_command(&in, &out);
		arg->ret = out.msg.res;
		arg->ret_origin = out.msg.err;
	} else {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		arg->ret_origin = TEE_ORIGIN_TEE;
	}

	smc_args->a0 = OPTEE_SMC_RETURN_OK;
}

void tee_entry_std(struct thread_smc_args *smc_args)
{
	paddr_t parg;
	struct optee_msg_arg *arg = NULL;	/* fix gcc warning */
	uint32_t num_params;

	if (smc_args->a0 != OPTEE_SMC_CALL_WITH_ARG) {
		EMSG("Unknown SMC 0x%" PRIx64, (uint64_t)smc_args->a0);
		DMSG("Expected 0x%x\n", OPTEE_SMC_CALL_WITH_ARG);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		return;
	}
	parg = (uint64_t)smc_args->a1 << 32 | smc_args->a2;
	if (!tee_pbuf_is_non_sec(parg, sizeof(struct optee_msg_arg)) ||
	    !ALIGNMENT_IS_OK(parg, struct optee_msg_arg) ||
	    !(arg = phys_to_virt(parg, MEM_AREA_NSEC_SHM))) {
		EMSG("Bad arg address 0x%" PRIxPA, parg);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
		return;
	}

	num_params = arg->num_params;
	if (!tee_pbuf_is_non_sec(parg, OPTEE_MSG_GET_ARG_SIZE(num_params))) {
		EMSG("Bad arg address 0x%" PRIxPA, parg);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADADDR;
		return;
	}

	thread_set_irq(true);	/* Enable IRQ for STD calls */
	switch (arg->cmd) {
	case OPTEE_MSG_CMD_OPEN_SESSION:
		entry_open_session(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_CLOSE_SESSION:
		entry_close_session(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_INVOKE_COMMAND:
		entry_invoke_command(smc_args, arg, num_params);
		break;
	case OPTEE_MSG_CMD_CANCEL:
		entry_cancel(smc_args, arg, num_params);
		break;
	default:
		EMSG("Unknown cmd 0x%x\n", arg->cmd);
		smc_args->a0 = OPTEE_SMC_RETURN_EBADCMD;
	}
}

static TEE_Result default_mobj_init(void)
{
	shm_mobj = mobj_phys_alloc(default_nsec_shm_paddr,
				   default_nsec_shm_size, SHM_CACHE_ATTRS,
				   CORE_MEM_NSEC_SHM);
	if (!shm_mobj)
		panic("Failed to register shared memory");

	mobj_sec_ddr = mobj_phys_alloc(tee_mm_sec_ddr.lo,
				       tee_mm_sec_ddr.hi - tee_mm_sec_ddr.lo,
				       SHM_CACHE_ATTRS, CORE_MEM_TA_RAM);
	if (!mobj_sec_ddr)
		panic("Failed to register secure ta ram");

	return TEE_SUCCESS;
}

driver_init_late(default_mobj_init);
