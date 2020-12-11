/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/handle.h>
#include <kernel/ts_store.h>
#include <kernel/user_mode_ctx_struct.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#ifndef KERNEL_LDELF_SYSCALLS_H
#define KERNEL_LDELF_SYSCALLS_H

struct system_ctx {
	struct handle_db db;
	const struct ts_store_ops *store_op;
};

void ta_bin_close(void *ptr);
TEE_Result ldelf_open_ta_binary(struct system_ctx *ctx, uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result ldelf_close_ta_binary(struct system_ctx *ctx, uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result ldelf_map_ta_binary(struct system_ctx *ctx,
			       struct user_mode_ctx *uctx,
			       uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result ldelf_copy_from_ta_binary(struct system_ctx *ctx,
				     uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result ldelf_set_prot(struct user_mode_ctx *uctx, uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result ldelf_remap(struct user_mode_ctx *uctx, uint32_t param_types,
		       TEE_Param params[TEE_NUM_PARAMS]);

#endif /* KERNEL_LDELF_SYSCALLS_H */
