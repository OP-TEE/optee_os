/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __KERNEL_OPTEE_RPMI_PRIVATE_H
#define __KERNEL_OPTEE_RPMI_PRIVATE_H

#include <mm/mobj.h>
#include <optee_rpmi.h>
#include <rpmi.h>
#include <rpmi_tee.h>
#include <stddef.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/* optee_rpmi_shm.c */

/* Shared-memory parcel registry. */
struct rpmi_parcel;
SLIST_HEAD(rpmi_shm_head, rpmi_parcel);

/* Parcel registry; lock protects lifecycle, mappings and pending slots. */
struct rpmi_shm_context {
	struct rpmi_shm_head entries;
	unsigned int lock;
	uint32_t self_id;
	uint32_t multisegment_max;
	size_t max_pages;
	size_t pending;
};

TEE_Result rpmi_shm_context_init(struct rpmi_shm_context *ctx, uint32_t self_id,
				 uint32_t multisegment_max, size_t max_pages);

/*
 * Get an active reference, accepting an unseen RW SHARE parcel if necessary.
 * Kernel address users must pair mobj_inc_map() with mobj_dec_map().
 * The caller supplies an initialized ctx, a valid channel and non-NULL mobj.
 */
TEE_Result rpmi_shm_get(struct rpmi_shm_context *ctx,
			struct mbox_chan *channel,
			uint32_t creator_id, uint64_t global_id,
			struct mobj **mobj);

TEE_Result rpmi_shm_unregister(struct rpmi_shm_context *ctx,
			       struct mbox_chan *channel,
			       uint32_t creator_id, uint64_t global_id);

/* optee_rpmi_msg.c */

/* Supported OP-TEE control responses, excluding the TEE_CALL header. */
union optee_rpmi_control_response {
	uint32_t status_code; /* Common first word of every response. */
	struct optee_rpmi_status_resp status;
	struct optee_rpmi_api_resp api;
	struct optee_rpmi_os_resp os;
	struct optee_rpmi_caps_resp caps;
};

TEE_Result optee_rpmi_dispatch(uint32_t self_id, const void *data,
			       size_t data_len, void *resp, size_t *resp_len);

#endif /* __KERNEL_OPTEE_RPMI_PRIVATE_H */
