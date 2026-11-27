/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_SIG_AUTH_H
#define __AUTH_PAS_SIG_AUTH_H

#include <tee_internal_api.h>

#include "pas_fuse.h"
#include "pas_mbn.h"
#include "pas_meta.h"

/*
 * Pick the firmware-segment hash-table digest size for @slot's signed
 * root cert, so the caller can size the hash table before parsing it.
 */
TEE_Result pas_sig_auth_segment_hash_len(const struct pas_md_slot *slot,
					 uint32_t *segment_hash_len);

/*
 * Check @hs and its ELF headers (@meta_data) before the image is loaded.
 *
 * Whatever @secboot_state is, @hs must carry OEM signature material and
 * metadata that does not make the image hardware independent, and the ELF
 * headers must match its hash table.
 *
 * Unless @secboot_state is PAS_SECBOOT_OFF, also check the metadata version
 * and device bindings, authenticate the signing chain and signature against
 * the root-of-trust @anchor, which is unused otherwise, and refuse an image
 * version below the anti-rollback floor.
 */
TEE_Result pas_sig_auth_verify_image(const struct pas_hash_segment_info *hs,
				     const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t pas_id,
				     uint32_t segment_hash_len,
				     const uint8_t *anchor,
				     enum pas_secboot_state secboot_state);

/*
 * Advance the device's PIL anti-rollback floor to @hs's OEM metadata
 * version, once the image it belongs to has been verified. Another image
 * sharing the counter may have raised the floor since INIT_IMAGE checked
 * this one, so an image now below the floor is refused with
 * TEE_ERROR_SECURITY. The floor only applies with secure boot, so nothing
 * changes when @secboot_state is PAS_SECBOOT_OFF or anti-rollback is not
 * enabled.
 */
TEE_Result pas_sig_auth_commit_rollback(const struct pas_hash_segment_info *hs,
					uint32_t pas_id,
					enum pas_secboot_state secboot_state);

#endif /* __AUTH_PAS_SIG_AUTH_H */
