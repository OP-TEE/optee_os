/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/user_ta.h>
#include <tee_api_types.h>

#ifndef KERNEL_LDELF_LOADER_H
#define KERNEL_LDELF_LOADER_H

TEE_Result ldelf_load_ldelf(struct user_ta_ctx *utc);
TEE_Result ldelf_init_with_ldelf(struct ts_session *sess,
				 struct user_ta_ctx *utc);
TEE_Result ldelf_dump_state(struct user_ta_ctx *utc);
TEE_Result ldelf_dump_ftrace(struct user_ta_ctx *utc, void *buf, size_t *blen);

#endif /* KERNEL_LDELF_LOADER_H */
