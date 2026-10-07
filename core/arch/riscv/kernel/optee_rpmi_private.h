/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __KERNEL_OPTEE_RPMI_PRIVATE_H
#define __KERNEL_OPTEE_RPMI_PRIVATE_H

#include <optee_rpmi.h>
#include <rpmi.h>
#include <rpmi_tee.h>
#include <stddef.h>
#include <tee_api_types.h>

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
