/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __KERNEL_OPTEE_RPMI_PRIVATE_H
#define __KERNEL_OPTEE_RPMI_PRIVATE_H

#include <drivers/mailbox.h>
#include <kernel/notif.h>
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

/* Create a SHM view at offset within a non-NULL RPMI parcel parent. */
struct mobj *rpmi_shm_view_alloc(struct mobj *parent, size_t offset,
				 size_t size);

size_t rpmi_shm_view_offset(struct mobj *mobj);
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
	struct optee_rpmi_call_resp call;
};

TEE_Result optee_rpmi_dispatch(uint32_t self_id, const void *data,
			       size_t data_len, void *resp, size_t *resp_len);

/* optee_rpmi_notif.c */

/* Asynchronous notification state and disabled-feature stubs. */
#ifdef CFG_CORE_ASYNC_NOTIF
enum optee_rpmi_notif_status {
	OPTEE_RPMI_NOTIF_NO_BUS,
	OPTEE_RPMI_NOTIF_DISABLED,
	OPTEE_RPMI_NOTIF_ENABLED,
};

/*
 * lifecycle_lock serializes bus changes, ENABLE/STARTED and the STOP callback.
 * lock protects the binding and is held throughout a synchronous signal raise.
 */
struct optee_rpmi_notif_state {
	unsigned int lifecycle_lock;
	unsigned int lock;
	enum optee_rpmi_notif_status status;
	uint32_t peer_id;
	uint32_t signal_id;
	struct notif_driver driver;
};

void notif_rpmi_init(struct optee_rpmi_notif_state *state);
int32_t optee_rpmi_signal_bus_setup(uint32_t sender_id, uint32_t bus_width,
				    uint32_t sender_signals);
void optee_rpmi_signal_bus_teardown(uint32_t sender_id);
TEE_Result optee_rpmi_enable_async_notif(uint32_t peer, uint32_t signal);
#else
static inline int32_t
optee_rpmi_signal_bus_setup(uint32_t sender_id __unused,
			    uint32_t bus_width __unused,
			    uint32_t sender_signals __unused)
{
	return RPMI_ERR_DENIED;
}

static inline void
optee_rpmi_signal_bus_teardown(uint32_t sender_id __unused)
{
}
#endif

/* optee_rpmi_core.c */

/*
 * Per-hart buffers for retrieving and completing forwarded RPMI requests.
 * request holds the retrieved packet; response and response_len describe
 * the reply passed to REQFWD completion on the same hart.
 *
 * A new secure thread copies its call arguments from request before it can
 * yield. Suspended call state therefore does not depend on these buffers.
 * The response buffer is still used when that thread yields or returns.
 * A resume is a new forwarded request and may arrive on another hart.
 */
struct optee_rpmi_abi_buffers {
	uint8_t *request;
	uint8_t response[RPMI_TEE_CALL_RESP_HEADER_SIZE +
			 sizeof(union optee_rpmi_control_response)];
	size_t response_len;
};

/* Immutable after activation except for per-hart buffers. */
struct optee_rpmi_core_state {
	struct optee_rpmi_abi_buffers abi_buffers[CFG_TEE_CORE_NB_CORE];
	struct mbox_client client;
	struct mbox_chan *reqfwd_channel;
	struct mbox_chan *tee_channel;
	bool probed;
	bool initialized;
	uint32_t signal_bus_feature;
};

/* One domain-wide backend; each state group retains its own synchronization. */
struct optee_rpmi_context {
	struct optee_rpmi_core_state core;
	struct rpmi_shm_context shm;
#ifdef CFG_CORE_ASYNC_NOTIF
	struct optee_rpmi_notif_state notif;
#endif
};

struct mbox_chan *optee_rpmi_channel(void);
struct rpmi_shm_context *optee_rpmi_shm_context(void);
#ifdef CFG_CORE_ASYNC_NOTIF
struct optee_rpmi_notif_state *optee_rpmi_notif_context(void);
#endif

/* Keep interrupts masked while accessing the current hart's buffers. */
struct optee_rpmi_abi_buffers *optee_rpmi_current_abi_buffers(void);
void optee_rpmi_set_yielding_response(TEE_Result status, uint32_t result,
				      uint32_t token);
void optee_rpmi_complete_and_loop(void) __noreturn;

/* Enter on the temporary stack; retrieval waits in firmware when idle. */
void optee_rpmi_loop(void) __noreturn;

/* optee_rpmi_thread.c */

TEE_Result thread_rpmi_handle_control(uint32_t caller, uint32_t op,
				      const void *service_data,
				      size_t service_len);

#endif /* __KERNEL_OPTEE_RPMI_PRIVATE_H */
