/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PROVISION_BACKEND_H__
#define __PROVISION_BACKEND_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Access to the fuse array used by the provisioning engine. Rows are
 * 64 bits wide, passed as two 32-bit words, low word first. All addresses are
 * RAW row addresses.
 */
struct provision_backend {
	/* Prepare the hardware for a batch of reads and writes */
	TEE_Result (*begin)(void);
	/* Release what begin() acquired. Called even after a failure. */
	TEE_Result (*end)(void);
	/* Read the corrected view of the row at @addr */
	TEE_Result (*read_row)(uint32_t addr, uint32_t *data);
	/* Program the row at @addr. @data is owned by the caller. */
	TEE_Result (*write_row)(uint32_t addr, uint32_t *data);
	/* Whether the row at @addr carries FEC bits. NULL if unsupported. */
	TEE_Result (*row_has_fec)(uint32_t addr, bool *has_fec);
	/*
	 * Whether further provisioning is locked by the write-permission
	 * fuses. NULL if the target cannot tell.
	 */
	TEE_Result (*is_write_locked)(bool *locked);
};

extern const struct provision_backend provision_backend_qfprom;
extern const struct provision_backend provision_backend_tme;

#endif /* __PROVISION_BACKEND_H__ */
