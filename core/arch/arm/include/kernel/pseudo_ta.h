/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef KERNEL_PSEUDO_TA_H
#define KERNEL_PSEUDO_TA_H

#include <assert.h>
#include <compiler.h>
#include <kernel/tee_ta_manager.h>
#include <scattered_array.h>
#include <tee_api_types.h>
#include <user_ta_header.h>
#include <util.h>

#define PTA_MANDATORY_FLAGS	(TA_FLAG_SINGLE_INSTANCE | \
				TA_FLAG_MULTI_SESSION | \
				TA_FLAG_INSTANCE_KEEP_ALIVE)

#define PTA_ALLOWED_FLAGS	(PTA_MANDATORY_FLAGS | \
				 TA_FLAG_SECURE_DATA_PATH | \
				 TA_FLAG_CONCURRENT | \
				 TA_FLAG_DEVICE_ENUM)

#define PTA_DEFAULT_FLAGS	PTA_MANDATORY_FLAGS

struct pseudo_ta_head {
	TEE_UUID uuid;
	const char *name;
	uint32_t flags;

	TEE_Result (*create_entry_point)(void);
	void (*destroy_entry_point)(void);
	TEE_Result (*open_session_entry_point)(uint32_t nParamTypes,
			TEE_Param pParams[TEE_NUM_PARAMS],
			void **ppSessionContext);
	void (*close_session_entry_point)(void *pSessionContext);
	TEE_Result (*invoke_command_entry_point)(void *pSessionContext,
			uint32_t nCommandID, uint32_t nParamTypes,
			TEE_Param pParams[TEE_NUM_PARAMS]);
};

#define pseudo_ta_register(...)	\
	SCATTERED_ARRAY_DEFINE_PG_ITEM(pseudo_tas, struct pseudo_ta_head) = \
		{ __VA_ARGS__ }

struct pseudo_ta_ctx {
	const struct pseudo_ta_head *pseudo_ta;
	struct tee_ta_ctx ctx;
};

bool is_pseudo_ta_ctx(struct tee_ta_ctx *ctx);

static inline struct pseudo_ta_ctx *to_pseudo_ta_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_pseudo_ta_ctx(ctx));
	return container_of(ctx, struct pseudo_ta_ctx, ctx);
}

TEE_Result tee_ta_init_pseudo_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);

#endif /* KERNEL_PSEUDO_TA_H */

