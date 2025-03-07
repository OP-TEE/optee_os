/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#ifndef __AMD_MAILBOX_DRIVER_H__
#define __AMD_MAILBOX_DRIVER_H__

#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define IPI_NON_BLOCK	U(0x0)
#define IPI_BLOCK	U(0x1)

TEE_Result mailbox_open(uint32_t remote_id, size_t payload_size);
TEE_Result mailbox_release(uint32_t remote_id, size_t payload_size);
TEE_Result mailbox_notify(uint32_t remote_id, void *payload,
			  size_t payload_size, uint32_t blocking);

#endif /* __AMD_MAILBOX_DRIVER_H__ */
