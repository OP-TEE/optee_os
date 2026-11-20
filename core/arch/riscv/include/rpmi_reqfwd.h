/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMI_REQFWD_H
#define __RPMI_REQFWD_H

#include <drivers/rpmi_mailbox.h>
#include <rpmi.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * The RPMI request-forwarding API retrieves requests assigned to the calling
 * hart and completes them with service responses. It handles chunked retrieval
 * and converts firmware errors to TEE_Result, leaving parsing and dispatch to
 * the caller.
 *
 *  - Keep exclusive ownership of the current request on its retrieving hart.
 *    Complete it there before another retrieval or migration.
 *  - Interrupt handlers must not start competing REQFWD operations. A yielding
 *    interrupt path must complete the current request before retrieving again.
 *  - Do not restart a partial retrieval or retry an uncertain completion.
 */

/* REQUEST_FORWARD service IDs. */
#define RPMI_REQFWD_RETRIEVE_CURRENT_MESSAGE	0x02
#define RPMI_REQFWD_COMPLETE_CURRENT_MESSAGE	0x03

/*
 * Retrieve a forwarded request, including its RPMI header, into data.
 * data_len_max is the maximum buffer size. On TEE_SUCCESS, len receives the
 * request size; otherwise it is zero. TEE_ERROR_SHORT_BUFFER means data is
 * too small.
 */
TEE_Result rpmi_reqfwd_retrieve(struct mbox_chan *channel,
				void *data, size_t data_len_max, size_t *len);

/*
 * Complete a request with len bytes from data, without an RPMI header.
 * On TEE_SUCCESS, num_messages receives the remaining queued-request count;
 * otherwise it is zero.
 */
TEE_Result rpmi_reqfwd_complete(struct mbox_chan *channel,
				void *data, size_t len, uint32_t *num_messages);

#endif /* __RPMI_REQFWD_H */
