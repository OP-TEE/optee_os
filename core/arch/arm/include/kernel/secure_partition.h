/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited.
 */
#ifndef __KERNEL_SECURE_PARTITION_H
#define __KERNEL_SECURE_PARTITION_H

#include <assert.h>
#include <config.h>
#include <ffa.h>
#include <kernel/embedded_ts.h>
#include <kernel/thread_spmc.h>
#include <kernel/user_mode_ctx_struct.h>
#include <mm/sp_mem.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee/entry_std.h>

TAILQ_HEAD(sp_sessions_head, sp_session);

struct sp_name_value_pair {
	uint32_t name[4];
	uint64_t value;
	uint64_t size;
};

/* SP entry arguments passed to SP image: see ABI in FF-A specification */
struct sp_ffa_init_info {
	uint32_t magic; /* FF-A */
	uint32_t count; /* Count of name value size pairs */
	struct sp_name_value_pair nvp[]; /* Array of name value size pairs */
};

enum sp_status { sp_idle, sp_busy, sp_preempted, sp_dead };

struct sp_session {
	struct ffa_rxtx rxtx;
	enum sp_status state;
	uint16_t endpoint_id;
	uint16_t caller_id;
	struct ts_session ts_sess;
	struct sp_ffa_init_info *info;
	unsigned int spinlock;
	TAILQ_ENTRY(sp_session) link;
};

struct sp_ctx {
	struct thread_ctx_regs sp_regs;
	struct sp_session *open_session;
	struct user_mode_ctx uctx;
	struct ts_ctx ts_ctx;
};

#ifdef CFG_SECURE_PARTITION
bool is_sp_ctx(struct ts_ctx *ctx);
#else
static inline bool is_sp_ctx(struct ts_ctx *ctx __unused)
{
	return false;
}
#endif

static inline struct sp_session *__noprof
to_sp_session(struct ts_session *sess)
{
	assert(is_sp_ctx(sess->ctx));
	return container_of(sess, struct sp_session, ts_sess);
}

static inline struct sp_ctx *to_sp_ctx(struct ts_ctx *ctx)
{
	assert(is_sp_ctx(ctx));
	return container_of(ctx, struct sp_ctx, ts_ctx);
}

struct sp_session *sp_get_session(uint32_t session_id);
TEE_Result sp_enter(struct thread_smc_args *args, struct sp_session *sp);
TEE_Result sp_partition_info_get_all(struct ffa_partition_info *fpi,
				     size_t *elem_count);

TEE_Result sp_find_session_id(const TEE_UUID *uuid, uint32_t *session_id);
bool sp_has_exclusive_access(struct sp_mem_map_region *mem,
			     struct user_mode_ctx *uctx);
TEE_Result sp_map_shared(struct sp_session *s,
			 struct sp_mem_receiver *receiver,
			 struct sp_mem *mem,
			 uint64_t *va);
TEE_Result sp_unmap_ffa_regions(struct sp_session *s, struct sp_mem *smem);

#define for_each_secure_partition(_sp) \
	SCATTERED_ARRAY_FOREACH(_sp, sp_images, struct embedded_ts)

#endif /* __KERNEL_SECURE_PARTITION_H */
