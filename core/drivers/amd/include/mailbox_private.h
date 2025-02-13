/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __AMD_MAILBOX_PRIVATE_H__
#define __AMD_MAILBOX_PRIVATE_H__

#include <kernel/mutex.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define IPI_BASE_MULTIPLIER             U(0x200)
#define IPI_OFFSET_MULTIPLIER           U(0x40)

#define IPI_BUFFER_MAX_WORDS            8

#define IPI_REQ_OFFSET                  U(0x0)
#define IPI_RESP_OFFSET                 U(0x20)

enum mailbox_api {
	/* IPI mailbox operations functions: */
	IPI_MAILBOX_OPEN = 0,
	IPI_MAILBOX_RELEASE,
	IPI_MAILBOX_STATUS_ENQUIRY,
	IPI_MAILBOX_NOTIFY,
	IPI_MAILBOX_ACK,
	IPI_MAILBOX_ENABLE_IRQ,
	IPI_MAILBOX_DISABLE_IRQ
};

struct ipi_info {
	uint32_t local;
	uint32_t remote;

	paddr_t buf;

	/* Exclusive access to the IPI shared buffer */
	struct mutex lock;

	void *rsp;
	void *req;
};

#define IPI_BASE_MULTIPLIER             U(0x200)
#define IPI_OFFSET_MULTIPLIER           U(0x40)

#define IPI_BUFFER_MAX_WORDS            8

#define IPI_REQ_OFFSET                  U(0x0)
#define IPI_RESP_OFFSET                 U(0x20)

#endif /* __AMD_MAILBOX_PRIVATE_H__ */
