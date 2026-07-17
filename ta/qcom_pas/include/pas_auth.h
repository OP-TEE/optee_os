/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_AUTH_H
#define __PAS_AUTH_H

#include <qcom_pas_priv.h>
#include <tee_internal_api.h>

/*
 * Firmware authentication backend for the PAS TA.
 *
 * INIT_IMAGE saves a TEE-private copy of the image metadata and, on devices
 * with secure-boot fuses blown, authenticates it (certificate chain,
 * signature, fuse-bound SW/HW binding and anti-rollback). AUTH_AND_RESET
 * re-hashes the segments the REE loaded against the metadata's per-segment
 * hash table before releasing the peripheral from reset.
 *
 * Segment-hash verification always runs; signature authentication runs as
 * a runtime decision inside pas_auth_authenticate() when the device is
 * provisioned for it.
 *
 * When CFG_QCOM_PAS_AUTH is disabled these calls compile to no-ops so the
 * command dispatch in qcom_pas.c stays free of build-config conditionals
 * and falls back to the plain PTA-side flow.
 */

#ifdef CFG_QCOM_PAS_AUTH
/*
 * pas_auth_save_metadata() - save a private copy of the INIT_IMAGE metadata
 * @s:      per-session context
 * @pt:     INIT_IMAGE invocation parameter types
 * @params: INIT_IMAGE invocation parameters; params[0].value.a is the
 *          peripheral pas_id, params[1].memref is the ELF header +
 *          program-header table + MBN hash segment
 *
 * Copies the metadata into TEE-private memory keyed by pas_id so the REE
 * cannot alter it between INIT_IMAGE and AUTH_AND_RESET.
 */
TEE_Result pas_auth_save_metadata(struct qcom_pas_session *s, uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS]);

/*
 * pas_auth_authenticate() - authenticate the saved metadata for @pas_id
 * @s:      per-session context
 * @pas_id: peripheral identifier the metadata belongs to
 *
 * Parses the MBN hash segment into the per-segment hash table. On devices
 * provisioned for secure boot this also verifies the certificate chain,
 * signature, SW/HW bindings and anti-rollback version; on unprovisioned
 * devices the signature step is skipped. Call after the matching
 * pas_auth_save_metadata() and the PTA INIT_IMAGE call.
 */
TEE_Result pas_auth_authenticate(struct qcom_pas_session *s, uint32_t pas_id);

/*
 * pas_auth_verify_reset() - re-verify loaded segments at AUTH_AND_RESET
 * @s:           per-session context
 * @pta_session: shared PAS PTA session handle
 * @pas_id:      peripheral identifier the metadata belongs to
 * @params:      AUTH_AND_RESET invocation parameters
 *
 * Packs the metadata and hash table into a single memref and hands it to
 * the PAS PTA's VERIFY_IMAGE command, which re-hashes each loaded firmware
 * segment against the authenticated table.
 */
TEE_Result pas_auth_verify_reset(struct qcom_pas_session *s,
				 TEE_TASessionHandle pta_session,
				 uint32_t pas_id,
				 TEE_Param params[TEE_NUM_PARAMS]);
#else
static inline TEE_Result
pas_auth_save_metadata(struct qcom_pas_session *s __unused,
		       uint32_t pt __unused,
		       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_auth_authenticate(struct qcom_pas_session *s __unused,
		      uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_auth_verify_reset(struct qcom_pas_session *s __unused,
		      TEE_TASessionHandle pta_session __unused,
		      uint32_t pas_id __unused,
		      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_QCOM_PAS_AUTH */

#endif /* __PAS_AUTH_H */
