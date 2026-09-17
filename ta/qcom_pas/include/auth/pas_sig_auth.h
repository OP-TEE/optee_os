/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_SIG_AUTH_H
#define __AUTH_PAS_SIG_AUTH_H

#include <tee_internal_api.h>

#include "pas_mbn.h"
#include "pas_meta.h"

/*
 * Pick the firmware-segment hash-table digest size for @slot's signed
 * root cert, so the caller can size the hash table before parsing it.
 */
TEE_Result pas_sig_auth_segment_hash_len(const struct pas_md_slot *slot,
					 uint32_t *segment_hash_len);

/*
 * Authenticate @hs's signing chain, root-of-trust, and device bindings,
 * then check the metadata against its ELF-header hash-table entry.
 */
TEE_Result pas_sig_auth_verify_image(const struct pas_hash_segment_info *hs,
				     const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t pas_id,
				     uint32_t segment_hash_len,
				     const uint8_t *anchor);

/*
 * Advance the device's PIL anti-rollback floor to @hs's OEM metadata
 * version, once the image it belongs to has been verified.
 */
TEE_Result pas_sig_auth_commit_rollback(const struct pas_hash_segment_info *hs,
					uint32_t pas_id);

#endif /* __AUTH_PAS_SIG_AUTH_H */
