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

/*
 * struct user_ta_ctx - user TA context
 * @entry_func:		Entry address in TA
 * @exidx_start:	32-bit TA: start of exception handling index table
 * @exidx_size:		32-bit TA: size of of exception handling index table
 * @is_32bit:		True if 32-bit TA, false if 64-bit TA
 * @open_sessions:	List of sessions opened by this TA
 * @cryp_states:	List of cryp states created by this TA
 * @objects:		List of storage objects opened by this TA
 * @storage_enums:	List of storage enumerators opened by this TA
 * @mobj_code:		Secure world memory for code and data
 * @mobj_stack:		Secure world memory for stack
 * @stack_addr:		Virtual address of stack
 * @load_addr:		ELF load addr (from TA address space)
 * @vm_info:		Virtual memory map of this context
 * @ta_time_offs:	Time reference used by the TA
 * @areas:		Memory areas registered by pager
 * @se_service:		Secure element services state
 * @vfp:		State of VFP registers
 * @ctx:		Generic TA context
 */
struct user_ta_ctx {
	uaddr_t entry_func;
	uaddr_t exidx_start;
	size_t exidx_size;
	bool is_32bit;
	struct tee_ta_session_head open_sessions;
	struct tee_cryp_state_head cryp_states;
	struct tee_obj_head objects;
	struct tee_storage_enum_head storage_enums;
	struct mobj *mobj_code;
	struct mobj *mobj_stack;
	vaddr_t stack_addr;
	vaddr_t load_addr;
	struct vm_info *vm_info;
	void *ta_time_offs;
	struct tee_pager_area_head *areas;
#if defined(CFG_SE_API)
	struct tee_se_service *se_service;
#endif
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_ta_ctx ctx;

};

#ifdef CFG_WITH_USER_TA
bool is_user_ta_ctx(struct tee_ta_ctx *ctx);
#else
static inline bool is_user_ta_ctx(struct tee_ta_ctx *ctx __unused)
{
	return false;
}
#endif

static inline struct user_ta_ctx *to_user_ta_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_user_ta_ctx(ctx));
	return container_of(ctx, struct user_ta_ctx, ctx);
}

struct user_ta_store_ops;

#ifdef CFG_WITH_USER_TA
TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);
TEE_Result tee_ta_register_ta_store(struct user_ta_store_ops *ops);
#else
static inline TEE_Result tee_ta_init_user_ta_session(
			const TEE_UUID *uuid __unused,
			struct tee_ta_session *s __unused)
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
