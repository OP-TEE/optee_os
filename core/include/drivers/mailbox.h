/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __DRIVERS_MAILBOX_H
#define __DRIVERS_MAILBOX_H

#include <kernel/dt_driver.h>
#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>

struct mbox_controller;
struct mbox_chan;

/* Caller-owned identity, kept alive until every claimed channel is released. */
struct mbox_client {
	void *priv;
};

/**
 * struct mbox_controller_ops - Mailbox controller operations
 * @get_channel: Resolve DT arguments into a controller-owned channel
 * @send_data_sync: Complete a synchronous transfer in the caller's context
 */
struct mbox_controller_ops {
	TEE_Result (*get_channel)(struct mbox_controller *controller,
				  struct dt_pargs *args,
				  struct mbox_chan **chan);
	TEE_Result (*send_data_sync)(struct mbox_chan *chan, void *message);
};

struct mbox_controller {
	const struct mbox_controller_ops *ops;
	/* Protects channel ownership, never held across a transfer. */
	unsigned int lock;
};

/* A mailbox channel exclusively assigned to one client. */
struct mbox_chan {
	struct mbox_controller *controller;
	struct mbox_client *client;
};

/* Controller and channels must remain allocated for the provider lifetime. */
TEE_Result mbox_controller_register_dt(struct mbox_controller *controller,
				       const void *fdt, int node);
TEE_Result mbox_request_channel(const void *fdt, int node, unsigned int index,
				struct mbox_client *client,
				struct mbox_chan **chan);
TEE_Result mbox_request_channel_byname(const void *fdt, int node,
				       const char *name,
				       struct mbox_client *client,
				       struct mbox_chan **chan);
/* Release a channel previously acquired by a client. */
void mbox_free_channel(struct mbox_chan *chan);
/* Provider retains no message pointers; provider defines send concurrency. */
TEE_Result mbox_send_message_sync(struct mbox_chan *chan, void *message);

#endif /* __DRIVERS_MAILBOX_H */
