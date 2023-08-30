/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2023, Arm Limited.
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

enum sp_status { sp_idle, sp_busy, sp_preempted, sp_dead };

struct sp_session {
	struct ffa_rxtx rxtx;
	enum sp_status state;
	uint16_t endpoint_id;
	uint16_t caller_id;
	uint32_t boot_order;
	struct ts_session ts_sess;
	unsigned int spinlock;
	const void *fdt;
	bool is_initialized;
	TEE_UUID ffa_uuid;
	uint32_t ns_int_mode;
	uint32_t ns_int_mode_inherited;
	TAILQ_ENTRY(sp_session) link;
};

struct sp_ctx {
	struct thread_ctx_regs sp_regs;
	struct sp_session *open_session;
	struct user_mode_ctx uctx;
	struct ts_ctx ts_ctx;
};

struct sp_image {
	struct embedded_ts image;
	const void *fdt;
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
TEE_Result sp_partition_info_get(uint32_t ffa_vers, void *buf, size_t buf_size,
				 const TEE_UUID *ffa_uuid, size_t *elem_count,
				 bool count_only);
bool sp_has_exclusive_access(struct sp_mem_map_region *mem,
			     struct user_mode_ctx *uctx);
TEE_Result sp_map_shared(struct sp_session *s,
			 struct sp_mem_receiver *receiver,
			 struct sp_mem *mem,
			 uint64_t *va);
TEE_Result sp_unmap_ffa_regions(struct sp_session *s, struct sp_mem *smem);

#define for_each_secure_partition(_sp) \
	SCATTERED_ARRAY_FOREACH(_sp, sp_images, struct sp_image)

struct fip_sp {
	struct sp_image sp_img;
	STAILQ_ENTRY(fip_sp) link;
};

STAILQ_HEAD(fip_sp_head, fip_sp);
extern struct fip_sp_head fip_sp_list;

#define for_each_fip_sp(_sp) \
	STAILQ_FOREACH(_sp, &fip_sp_list, link)

#endif /* __KERNEL_SECURE_PARTITION_H */
