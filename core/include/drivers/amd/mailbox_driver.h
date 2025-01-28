/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __MAILBOX_DRIVER_H__
#define __MAILBOX_DRIVER_H__

#include <platform_config.h>
#include <tee_api_types.h>
#include <util.h>

enum mailbox_api {
	/* IPI mailbox operations functions: */
	IPI_MAILBOX_OPEN = 0x1000,
	IPI_MAILBOX_RELEASE,
	IPI_MAILBOX_STATUS_ENQUIRY,
	IPI_MAILBOX_NOTIFY,
	IPI_MAILBOX_ACK,
	IPI_MAILBOX_ENABLE_IRQ,
	IPI_MAILBOX_DISABLE_IRQ
};

#define IPI_NON_BLOCK	0x0U
#define IPI_BLOCK	0x1U

struct ipi_info_t {
	uint32_t local;
	uint32_t remote;

	paddr_t buf;

	/* Exclusive access to the IPI shared buffer */
	struct mutex lock;

	void *rsp;
	void *req;
};

TEE_Result mailbox_open(uint32_t remote_id, size_t payload_size);
TEE_Result mailbox_release(uint32_t remote_id, size_t payload_size);
TEE_Result mailbox_notify(uint32_t remote_id, void *payload,
			  size_t payload_size, uint32_t blocking);

#endif /* __MAILBOX_DRIVER_H__ */
