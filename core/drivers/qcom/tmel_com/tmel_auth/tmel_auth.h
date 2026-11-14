/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_AUTH_H
#define __TMEL_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <types_ext.h>
#include <util.h>

/* Authentication flags for struct tmel_sec_auth_params::flags */
#define TMEL_AUTH_FLAG_NS_INTEGRITY	BIT32(0)

/* Request sizes in bytes, per the PARAM_IDs in tmemessages_uids.h */
#define TMEL_SEC_AUTH_V1_REQ_SIZE	44
#define TMEL_SEC_AUTH_V2_REQ_SIZE	60

/* Physically contiguous buffer, addressed as TME-Lite sees it */
struct tmel_auth_buf {
	paddr_t pa;
	size_t len;
};

/*
 * ELF image authentication request.
 *
 * @sw_id:		Software ID the image is authenticated against
 * @elf_buf:		ELF headers and hash segment
 * @region_list:	Optional regions the image may be loaded to, { 0, 0 }
 *			when unused
 * @relocate:		Non-zero to let TME-Lite relocate the image
 * @flags:		TMEL_AUTH_FLAG_*, only honoured by V2 SoCs
 *
 * TME-Lite reads the buffers directly from memory: they must lie below 4 GiB
 * and the caller must have cleaned them from the data cache. The remaining
 * fields are outputs, valid on success; @key_handle is only set by V2 SoCs.
 */
struct tmel_sec_auth_params {
	uint32_t sw_id;
	struct tmel_auth_buf elf_buf;
	struct tmel_auth_buf region_list;
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
 * Authenticate an ELF image with TME-Lite, using the request version of the
 * SoC (TMEL_AUTH_VERSION). Fails with TEE_ERROR_BAD_PARAMETERS for invalid
 * @params or buffers, TEE_ERROR_NOT_SUPPORTED for an invalid version and
 * TEE_ERROR_BAD_FORMAT if the request has an unexpected size.
 */
TEE_Result tmel_secure_auth(struct tmel_sec_auth_params *params);

#endif /* __TMEL_AUTH_H */
