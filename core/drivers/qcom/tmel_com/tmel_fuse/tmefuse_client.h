/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEFUSE_CLIENT_H
#define __TMEFUSE_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/* A QFPROM row: its address and its two data words */
struct tme_fuse_row {
	uint32_t addr;
	uint32_t lsb;
	uint32_t msb;
};

struct tme_fuse_write_row_msg {
	uint32_t status;
	struct tme_fuse_row row;
};

struct tme_fuse_write_rows_msg {
	uint32_t status;
	uint32_t rows;
	uint32_t rows_len;
};

struct tme_fuse_oem_mrc_msg {
	uint32_t activate;
	uint32_t revoke;
	uint32_t status;
};

TEE_Result tme_fuse_write_row(const struct tme_fuse_row *row);

/* Program @count rows in one request, for regions TME-Lite takes whole */
TEE_Result tme_fuse_write_rows(const struct tme_fuse_row *rows, size_t count);

/* Update the OEM MRC state with the @activate and @revoke vectors */
TEE_Result tme_fuse_update_oem_mrc(uint32_t activate, uint32_t revoke);

#endif /* __TMEFUSE_CLIENT_H */
