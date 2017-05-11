/*
 * Copyright (c) 2015, Linaro Limited
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
#ifndef KERNEL_USER_TA_H
#define KERNEL_USER_TA_H

#include <assert.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/tee_mm.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

TAILQ_HEAD(tee_cryp_state_head, tee_cryp_state);
TAILQ_HEAD(tee_obj_head, tee_obj);
TAILQ_HEAD(tee_storage_enum_head, tee_storage_enum);

struct user_ta_ctx {
	uaddr_t entry_func;
	uaddr_t exidx_start;	/* 32-bit TA: exception handling index table */
	size_t exidx_size;
	bool is_32bit;		/* true if 32-bit ta, false if 64-bit ta */
	/* list of sessions opened by this TA */
	struct tee_ta_session_head open_sessions;
	/* List of cryp states created by this TA */
	struct tee_cryp_state_head cryp_states;
	/* List of storage objects opened by this TA */
	struct tee_obj_head objects;
	/* List of storage enumerators opened by this TA */
	struct tee_storage_enum_head storage_enums;
	struct mobj *mobj_code; /* secure world memory */
	struct mobj *mobj_stack; /* stack */
	uint32_t load_addr;	/* elf load addr (from TAs address space) */
	uint32_t context;	/* Context ID of the process */
	struct tee_mmu_info *mmu;	/* Saved MMU information (ddr only) */
	void *ta_time_offs;	/* Time reference used by the TA */
	struct tee_pager_area_head *areas;
#if defined(CFG_SE_API)
	struct tee_se_service *se_service;
#endif
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_ta_ctx ctx;

};

static inline bool is_user_ta_ctx(struct tee_ta_ctx *ctx)
{
	return !!(ctx->flags & TA_FLAG_USER_MODE);
}

static inline struct user_ta_ctx *to_user_ta_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_user_ta_ctx(ctx));
	return container_of(ctx, struct user_ta_ctx, ctx);
}

struct user_ta_store_ops;

#ifdef CFG_WITH_USER_TA
TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);
TEE_Result tee_ta_register_ta_store(const struct user_ta_store_ops *ops);
#else
static inline TEE_Result tee_ta_init_user_ta_session(
			const TEE_UUID *uuid __unused,
			struct tee_ta_session *s __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static inline TEE_Result tee_ta_register_ta_store(
			const struct user_ta_store_ops *ops __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /*KERNEL_USER_TA_H*/
