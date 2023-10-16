/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */
#ifndef __KERNEL_USER_TA_H
#define __KERNEL_USER_TA_H

#include <assert.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/thread.h>
#include <mm/file.h>
#include <mm/tee_mm.h>
#include <scattered_array.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

TAILQ_HEAD(tee_cryp_state_head, tee_cryp_state);
TAILQ_HEAD(tee_obj_head, tee_obj);
TAILQ_HEAD(tee_storage_enum_head, tee_storage_enum);
SLIST_HEAD(load_seg_head, load_seg);

/*
 * struct user_ta_ctx - user TA context
 * @open_sessions:	List of sessions opened by this TA
 * @cryp_states:	List of cryp states created by this TA
 * @objects:		List of storage objects opened by this TA
 * @storage_enums:	List of storage enumerators opened by this TA
 * @ta_time_offs:	Time reference used by the TA
 * @uctx:		Generic user mode context
 * @ctx:		Generic TA context
 */
struct user_ta_ctx {
	struct tee_ta_session_head open_sessions;
	struct tee_cryp_state_head cryp_states;
	struct tee_obj_head objects;
	struct tee_storage_enum_head storage_enums;
	void *ta_time_offs;
	struct user_mode_ctx uctx;
	struct tee_ta_ctx ta_ctx;
};

#ifdef CFG_WITH_USER_TA
bool is_user_ta_ctx(struct ts_ctx *ctx);
#else
static inline bool __noprof is_user_ta_ctx(struct ts_ctx *ctx __unused)
{
	return false;
}
#endif

static inline struct user_ta_ctx *to_user_ta_ctx(struct ts_ctx *ctx)
{
	assert(is_user_ta_ctx(ctx));
	return container_of(ctx, struct user_ta_ctx, ta_ctx.ts_ctx);
}

#ifdef CFG_WITH_USER_TA
TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);
#else
static inline TEE_Result tee_ta_init_user_ta_session(
			const TEE_UUID *uuid __unused,
			struct tee_ta_session *s __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}
#endif


#endif /*__KERNEL_USER_TA_H*/
