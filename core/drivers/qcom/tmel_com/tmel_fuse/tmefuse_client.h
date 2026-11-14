/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEFUSE_CLIENT_H
#define __TMEFUSE_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

struct tme_fuse_payload {
	uint32_t fuse_addr;
	uint32_t lsb_val;
	uint32_t msb_val;
};

TEE_Result tme_fuse_write_row(const struct tme_fuse_payload *fuse);

TEE_Result tme_fuse_write_multiple_rows(const struct tme_fuse_payload *fuse,
					size_t num_rows);

TEE_Result tme_oem_mrc_state_update(uint32_t activate_vector,
				    uint32_t revocate_vector);

#endif /* __TMEFUSE_CLIENT_H */
