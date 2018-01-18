/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
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
TEE_Result user_ta_get_ctx(const TEE_UUID *uuid, struct tee_ta_ctx **ctx);
TEE_Result tee_ta_register_ta_store(struct user_ta_store_ops *ops);
#else
static inline TEE_Result user_ta_get_ctx(const TEE_UUID *uuid __unused,
					 struct tee_ta_ctx **ctx __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static inline TEE_Result tee_ta_register_ta_store(
			struct user_ta_store_ops *ops __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /*KERNEL_USER_TA_H*/
