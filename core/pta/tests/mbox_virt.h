/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, STMicroelectronics
 */
#ifndef CORE_PTA_TESTS_MBOX_VIRT_H
#define CORE_PTA_TESTS_MBOX_VIRT_H

#include <drivers/mailbox_controller.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Virtual mailbox controller used to exercise the mailbox framework. It
 * loops messages back through a single slot: a message sent is received
 * back, a second send before the receive reports TEE_ERROR_BUSY and a
 * receive on an empty slot reports TEE_ERROR_NO_DATA, except for the
 * MBOX_VIRT_BLOCKING flavor which waits for the message.
 */

#define MBOX_VIRT_MSG_SIZE	8

/*
 * Number of channels of a controller, selected by the first specifier cell
 * (channel 0 without specifier). They share the controller slot: a message
 * sent on a channel is received on any of them.
 */
#define MBOX_VIRT_CHAN_COUNT	2

/* Maximum time a MBOX_VIRT_BLOCKING recv_sync waits for a message */
#define MBOX_VIRT_WAIT_MS	5000
#define MBOX_VIRT_POLL_MS	50

struct mbox_virt_msg {
	uint8_t data[MBOX_VIRT_MSG_SIZE];
};

/* Each flavor is a controller registered with a distinct set of ops */
enum mbox_virt_flavor {
	/* All operations implemented */
	MBOX_VIRT_FULL,
	/* No recv_sync operation */
	MBOX_VIRT_NO_RECV,
	/* No free_channel operation */
	MBOX_VIRT_NO_FREE,
	/* request_channel returns success with a NULL channel */
	MBOX_VIRT_NULL_CHAN,
	/* Operations return the error set with mbox_virt_set_error() */
	MBOX_VIRT_FAILING,
	/*
	 * recv_sync waits for a message to be sent, using an asynchronous
	 * notification. Requires CFG_CORE_ASYNC_NOTIF, else mbox_virt_get()
	 * returns TEE_ERROR_NOT_SUPPORTED.
	 */
	MBOX_VIRT_BLOCKING,
	MBOX_VIRT_FLAVOR_COUNT
};

struct mbox_virt_stats {
	unsigned int requested;
	unsigned int freed;
	unsigned int sent;
	unsigned int received;
	/* Last specifier given to request_channel */
	size_t last_args_count;
	uint32_t last_arg0;
};

/* Get the controller of @flavor, registered on first use */
TEE_Result mbox_virt_get(enum mbox_virt_flavor flavor,
			 struct mbox_controller **ctrl);

/* Statistics of the controller, @ctrl must come from mbox_virt_get() */
struct mbox_virt_stats *mbox_virt_stats(struct mbox_controller *ctrl);

/* Error returned by all operations of a MBOX_VIRT_FAILING controller */
void mbox_virt_set_error(struct mbox_controller *ctrl, TEE_Result res);

/* Release the channels, clear the stats, error and pending message */
void mbox_virt_reset(struct mbox_controller *ctrl);

#endif /*CORE_PTA_TESTS_MBOX_VIRT_H*/
