/*
 * Copyright (c) 2017, Linaro Limited
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
#include <bench.h>
#include <compiler.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/pseudo_ta.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <pta_benchmark.h>
#include <string.h>
#include <string_ext.h>
#include <stdio.h>
#include <trace.h>

#define TA_NAME		"benchmark.ta"

struct tee_ts_global *bench_ts_global;
static struct mutex bench_reg_mu = MUTEX_INITIALIZER;

static TEE_Result rpc_reg_global_buf(uint64_t type, paddr_t phta, size_t size)
{
	struct optee_msg_param rpc_params;

	memset(&rpc_params, 0, sizeof(rpc_params));
	rpc_params.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
	rpc_params.u.value.a = type;
	rpc_params.u.value.b = (uint64_t)phta;
	rpc_params.u.value.c = size;

	return thread_rpc_cmd(OPTEE_MSG_RPC_CMD_BENCH_REG, 1, &rpc_params);
}

static TEE_Result register_benchmark_memref(uint32_t type,
				TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result res;

	if ((TEE_PARAM_TYPE_GET(type, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
		(TEE_PARAM_TYPE_GET(type, 1) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 2) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 3) != TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * We accept only non-secure buffers, as we later perform
	 * registration of this buffer in NS layers
	 * (optee linux kmod/optee client)
	 */
	if (!tee_vbuf_is_non_sec(p[0].memref.buffer, p[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&bench_reg_mu);

	/* Check if we have already registered buffer */
	if (bench_ts_global) {
		EMSG("Timestamp buffer was already registered\n");
		mutex_unlock(&bench_reg_mu);
		return TEE_ERROR_BAD_STATE;
	}

	DMSG("Registering timestamp buffer, addr = %p, paddr = %" PRIxPA "\n",
			p[0].memref.buffer,
			virt_to_phys(p[0].memref.buffer));
	bench_ts_global = p[0].memref.buffer;

	mutex_unlock(&bench_reg_mu);

	/* Send back to the optee linux kernel module */
	res = rpc_reg_global_buf(OPTEE_MSG_RPC_CMD_BENCH_REG_NEW,
			virt_to_phys((void *)bench_ts_global),
			sizeof(struct tee_ts_global) +
			sizeof(struct tee_ts_cpu_buf) *
			bench_ts_global->cores);

	return res;
}

static TEE_Result get_benchmark_memref(uint32_t type,
				TEE_Param p[TEE_NUM_PARAMS])
{
	if ((TEE_PARAM_TYPE_GET(type, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) ||
		(TEE_PARAM_TYPE_GET(type, 1) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 2) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 3) != TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mutex_lock(&bench_reg_mu);

	DMSG("Sending back timestamp buffer paddr = %p\n",
		(void *)virt_to_phys(bench_ts_global));
	p[0].value.a = virt_to_phys(bench_ts_global);
	p[0].value.b = sizeof(struct tee_ts_global) +
			sizeof(struct tee_ts_cpu_buf) * bench_ts_global->cores;

	mutex_unlock(&bench_reg_mu);

	return TEE_SUCCESS;
}

static TEE_Result unregister_benchmark(uint32_t type,
				TEE_Param p[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res;

	if ((TEE_PARAM_TYPE_GET(type, 0) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 1) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 2) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 3) != TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	mutex_lock(&bench_reg_mu);

	DMSG("Unregistering benchmark, timestamp buffer paddr = %p\n",
		(void *)virt_to_phys(bench_ts_global));
	bench_ts_global = NULL;

	mutex_unlock(&bench_reg_mu);

	res = rpc_reg_global_buf(OPTEE_MSG_RPC_CMD_BENCH_REG_DEL, 0, 0);

	return res;
}

static TEE_Result invoke_command(void *session_ctx __unused,
		uint32_t cmd_id, uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case BENCHMARK_CMD_REGISTER_MEMREF:
		return register_benchmark_memref(param_types, params);
	case BENCHMARK_CMD_GET_MEMREF:
		return get_benchmark_memref(param_types, params);
	case BENCHMARK_CMD_UNREGISTER:
		return unregister_benchmark(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = BENCHMARK_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);

void bm_timestamp(void)
{
	struct tee_ts_cpu_buf *cpu_buf;
	struct tee_time_st ts_data;
	uint64_t ts_i;
	void *ret_addr;
	uint32_t cur_cpu;
	uint32_t exceptions;

	if (!bench_ts_global)
		return;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	cur_cpu = get_core_pos();

	if (cur_cpu >= bench_ts_global->cores) {
		thread_unmask_exceptions(exceptions);
		return;
	}

	ret_addr = __builtin_return_address(0);

	cpu_buf = &bench_ts_global->cpu_buf[cur_cpu];
	ts_i = cpu_buf->head++;
	ts_data.cnt = read_pmu_ccnt() * TEE_BENCH_DIVIDER;
	ts_data.addr = (uintptr_t)ret_addr;
	ts_data.src = TEE_BENCH_CORE;
	cpu_buf->stamps[ts_i & TEE_BENCH_MAX_MASK] = ts_data;

	thread_unmask_exceptions(exceptions);
}
