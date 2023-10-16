/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/ts_manager.h>
#include <kernel/user_mode_ctx.h>
#include <tee_api_types.h>

#ifndef __KERNEL_LDELF_LOADER_H
#define __KERNEL_LDELF_LOADER_H

TEE_Result ldelf_load_ldelf(struct user_mode_ctx *uctx);
TEE_Result ldelf_init_with_ldelf(struct ts_session *sess,
				 struct user_mode_ctx *uctx);
TEE_Result ldelf_dump_state(struct user_mode_ctx *uctx);
TEE_Result ldelf_dump_ftrace(struct user_mode_ctx *uctx,
			     void *buf, size_t *blen);
TEE_Result ldelf_dlopen(struct user_mode_ctx *uctx, TEE_UUID *uuid,
			uint32_t flags);
TEE_Result ldelf_dlsym(struct user_mode_ctx *uctx, TEE_UUID *uuid,
		       const char *sym, size_t symlen, vaddr_t *val);

#endif /* __KERNEL_LDELF_LOADER_H */
