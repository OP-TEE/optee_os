/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, ARM Limited. All rights reserved.
 */

#ifndef __KERNEL_TPM_H__
#define __KERNEL_TPM_H__

#include <tee_api_types.h>

#ifdef CFG_CORE_TPM_EVENT_LOG

/*
 * Returns the TPM Event Log information previously retrieved
 * by @tpm_map_log_area.
 *
 * @buf Pointer to a buffer where to store a copy of the TPM Event log.
 */
TEE_Result tpm_get_event_log(void *buf, size_t *size);

/*
 * Reads the TPM Event log information and store it internally.
 * If support for DTB is enabled, it will read the parameters there.
 * Otherwise, it will use the constant parameters hardcoded in conf.mk.
 *
 * @fdt Pointer to the DTB blob where the TPM Event log information
 * is expected to be.
 */
void tpm_map_log_area(void *fdt);

#else

static inline TEE_Result tpm_get_event_log(void *buf __unused,
					   size_t *size __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void tpm_map_log_area(void *fdt __unused)
{}

#endif /* CFG_CORE_TPM_EVENT_LOG */

#endif /* __KERNEL_TPM_H__ */
