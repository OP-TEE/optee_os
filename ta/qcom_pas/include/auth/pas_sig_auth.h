/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_SIG_AUTH_H
#define __PAS_SIG_AUTH_H

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
 * then check the metadata preamble against its hash-table entry.
 */
TEE_Result pas_sig_auth_verify_image(const struct pas_mbn *hs,
				     const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t pas_id,
				     uint32_t segment_hash_len,
				     const uint8_t *anchor);

#endif /* __PAS_SIG_AUTH_H */
