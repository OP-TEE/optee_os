// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <bench.h>
#include <compiler.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/pseudo_ta.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <optee_rpc_cmd.h>
#include <pta_benchmark.h>
#include <stdio.h>
#include <string_ext.h>
#include <string.h>
#include <trace.h>

#define TA_NAME		"benchmark.ta"
#define TA_PRINT_PREFIX	"Benchmark: "

static struct tee_ts_global *bench_ts_global;
static size_t bench_ts_size;

static struct mutex bench_reg_mu = MUTEX_INITIALIZER;
static struct mobj *bench_mobj;

static TEE_Result rpc_reg_global_buf(uint64_t type, paddr_t phta, size_t size)
{
	struct thread_param tpm = THREAD_PARAM_VALUE(IN, type, phta, size);

	return thread_rpc_cmd(OPTEE_RPC_CMD_BENCH_REG, 1, &tpm);
}

static TEE_Result alloc_benchmark_buffer(uint32_t type,
				TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result res;

	if ((TEE_PARAM_TYPE_GET(type, 0) != TEE_PARAM_TYPE_VALUE_INOUT) ||
		(TEE_PARAM_TYPE_GET(type, 1) != TEE_PARAM_TYPE_VALUE_INPUT) ||
		(TEE_PARAM_TYPE_GET(type, 2) != TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(type, 3) != TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mutex_lock(&bench_reg_mu);

	/* Check if we have already registered buffer */
	if (bench_ts_global) {
		EMSG(TA_PRINT_PREFIX
			"timestamp buffer was already registered");
		mutex_unlock(&bench_reg_mu);
		return TEE_ERROR_BAD_STATE;
	}

	bench_ts_size = sizeof(struct tee_ts_global) +
		p[1].value.a * sizeof(struct tee_ts_cpu_buf);
	if (!bench_ts_size) {
		EMSG(TA_PRINT_PREFIX
			"invalid timestamp buffer size");
		mutex_unlock(&bench_reg_mu);
		return TEE_ERROR_BAD_STATE;
	}

	bench_mobj = thread_rpc_alloc_global_payload(bench_ts_size);
	if (!bench_mobj) {
		EMSG(TA_PRINT_PREFIX
			"can't create mobj for timestamp buffer");
		mutex_unlock(&bench_reg_mu);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	bench_ts_global = (struct tee_ts_global *)mobj_get_va(bench_mobj, 0);
	if (!bench_ts_global) {
		thread_rpc_free_global_payload(bench_mobj);
		bench_mobj = NULL;

		mutex_unlock(&bench_reg_mu);
		return TEE_ERROR_BAD_STATE;
	}

	memset((void *)bench_ts_global, 0, bench_ts_size);
	bench_ts_global->cores = p[1].value.a;

	DMSG(TA_PRINT_PREFIX
		"allocated timestamp buffer, addr = %p",
		(void *)bench_ts_global);

	mutex_unlock(&bench_reg_mu);

	/* Send back to the optee linux kernel module */
	res = rpc_reg_global_buf(OPTEE_MSG_RPC_CMD_BENCH_REG_NEW,
			virt_to_phys((void *)bench_ts_global),
			bench_ts_size);

	p[0].value.a = virt_to_phys((void *)bench_ts_global);
	p[0].value.b = bench_ts_size;

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

	DMSG(TA_PRINT_PREFIX "Sending back timestamp buffer paddr = %p",
		(void *)virt_to_phys((void *)bench_ts_global));

	if (bench_ts_global) {
		p[0].value.a = virt_to_phys((void *)bench_ts_global);
		p[0].value.b = bench_ts_size;
	} else {
		p[0].value.a = 0;
		p[0].value.b = 0;
	}

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

	DMSG(TA_PRINT_PREFIX "Unregister benchmark ts buffer paddr = %p",
		(void *)virt_to_phys((void *)bench_ts_global));
	bench_ts_global = NULL;

	mutex_unlock(&bench_reg_mu);

	res = rpc_reg_global_buf(OPTEE_MSG_RPC_CMD_BENCH_REG_DEL, 0, 0);

	thread_rpc_free_global_payload(bench_mobj);
	bench_mobj = NULL;

	return res;
}

static TEE_Result invoke_command(void *session_ctx __unused,
		uint32_t cmd_id, uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case BENCHMARK_CMD_ALLOCATE_BUF:
		return alloc_benchmark_buffer(param_types, params);
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
	ts_data.cnt = read_pmccntr() * TEE_BENCH_DIVIDER;
	ts_data.addr = (uintptr_t)ret_addr;
	ts_data.src = TEE_BENCH_CORE;
	cpu_buf->stamps[ts_i & TEE_BENCH_MAX_MASK] = ts_data;

	thread_unmask_exceptions(exceptions);
}
