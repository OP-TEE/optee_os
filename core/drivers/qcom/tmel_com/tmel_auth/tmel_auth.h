/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_AUTH_H
#define __TMEL_AUTH_H

#include <stdint.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <util.h>

/* Authentication flags for struct tmel_sec_auth_params::flags */
#define TMEL_AUTH_FLAG_NS_INTEGRITY	BIT32(0)

/*
 * ELF image authentication request.
 *
 * @sw_id:		Software ID the image is authenticated against
 * @elf_buf:		Physical address and length of the ELF headers and
 *			hash segment
 * @region_list:	Optional list of regions the image may be loaded to,
 *			{ 0, 0 } when unused
 * @relocate:		Non-zero to let TME-Lite relocate the image
 * @flags:		TMEL_AUTH_FLAG_*, only honoured by V2 SoCs
 *
 * The remaining fields are outputs, valid when tmel_secure_auth() succeeds.
 * @status and @extended_error carry the TME-Lite result for diagnostics.
 * @key_handle is only set by V2 SoCs.
 *
 * The buffers in @elf_buf and @region_list are read by TME-Lite directly from
 * memory, the caller must make them visible to it (cache maintenance) before
 * the call.
 */
struct tmel_sec_auth_params {
	uint32_t sw_id;
	struct tmel_buf_desc elf_buf;
	struct tmel_buf_desc region_list;
	uint32_t relocate;
	uint32_t flags;

	uint32_t first_seg_addr;
	uint32_t first_seg_len;
	uint32_t entry_addr;
	uint32_t extended_error;
	uint32_t status;
	uint32_t key_handle;
};

/*
 * Authenticate an ELF image with TME-Lite, using the request version the
 * SoC supports (TMEL_AUTH_VERSION). Returns TEE_SUCCESS only if TME-Lite
 * accepted the image.
 */
TEE_Result tmel_secure_auth(struct tmel_sec_auth_params *params);

#endif /* __TMEL_AUTH_H */
