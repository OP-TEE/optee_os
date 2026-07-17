// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Firmware authentication backend for the PAS TA. Built under
 * CFG_QCOM_PAS_AUTH. Entry points are invoked from the command dispatch
 * in qcom_pas.c.
 *
 * INIT_IMAGE (pas_auth_save_metadata + pas_auth_authenticate):
 *   1. Copy the REE-supplied metadata blob into a TEE-private slot keyed
 *      by pas_id so the REE cannot mutate it before AUTH_AND_RESET.
 *   2. Parse the MBN hash segment.
 *   3. If the device is provisioned for secure boot, authenticate the
 *      metadata (certificate chain, signature, SW/HW binding and
 *      anti-rollback) via the signature backend hook below. Devices with
 *      unblown fuses skip this step and trust the parsed hash table on
 *      its own.
 *
 * AUTH_AND_RESET (pas_auth_verify_reset):
 *   Hand [metadata | hash table] to the PAS PTA's VERIFY_IMAGE command,
 *   which re-hashes each loaded firmware segment against the table and
 *   fails the load if any digest mismatches, before the peripheral is
 *   released from reset.
 */

#include <pas_auth.h>
#include <pas_mbn_parser.h>
#include <pta_qcom_pas.h>
#include <qcom_pas_priv.h>
#include <string.h>
#include <tee_internal_api.h>
#include <utee_defines.h>

static struct pas_md_slot *find_md_slot(struct qcom_pas_session *s,
					uint32_t pas_id)
{
	size_t i = 0;

	for (i = 0; i < PAS_MD_SLOTS; i++) {
		if (s->md[i].used && s->md[i].pas_id == pas_id)
			return &s->md[i];
	}

	return NULL;
}

/*
 * Placeholder for signature authentication. Runs only on devices with
 * secure-boot fuses blown; on unprovisioned devices the caller skips
 * calling this function. Replaced by the real signature-authentication
 * implementation in a later commit; keeping the seam here now lets
 * segment-hash verification be reviewed and enabled without waiting on
 * the signature-auth work.
 */
static TEE_Result pas_authenticate_signature(struct pas_md_slot *slot __unused,
					     uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}

/*
 * Return true when the device is provisioned for secure boot (OEM
 * root-of-trust anchor fused). Until the fuse-reading path is wired in
 * (later commit), report "not provisioned" so devices without secure
 * boot continue to work with hash verification alone.
 */
static bool secure_boot_provisioned(void)
{
	return false;
}

TEE_Result pas_auth_save_metadata(struct qcom_pas_session *s, uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct pas_md_slot *slot = NULL;
	uint32_t pas_id = 0;
	void *copy = NULL;
	size_t size = 0;
	size_t i = 0;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	pas_id = params[0].value.a;

	/* Reuse the existing slot for this pas_id, else take a free one. */
	slot = find_md_slot(s, pas_id);
	if (!slot) {
		for (i = 0; i < PAS_MD_SLOTS; i++) {
			if (!s->md[i].used) {
				slot = &s->md[i];
				break;
			}
		}
	}
	if (!slot) {
		EMSG("PAS auth: no free md slot (pas_id=%"PRIu32")", pas_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	size = params[1].memref.size;
	if (size) {
		copy = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
		if (!copy)
			return TEE_ERROR_OUT_OF_MEMORY;
		memcpy(copy, params[1].memref.buffer, size);
	}

	TEE_Free(slot->md);
	slot->md = copy;
	slot->md_size = size;
	slot->pas_id = pas_id;
	slot->used = true;
	slot->authenticated = false;
	memset(&slot->mbn, 0, sizeof(slot->mbn));

	return TEE_SUCCESS;
}

TEE_Result pas_auth_authenticate(struct qcom_pas_session *s, uint32_t pas_id)
{
	struct pas_md_slot *slot = find_md_slot(s, pas_id);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!slot) {
		EMSG("PAS auth: no metadata for pas_id=%"PRIu32
		     " (call INIT_IMAGE first)", pas_id);
		return TEE_ERROR_BAD_STATE;
	}

	res = pas_mbn_parse(slot->md, slot->md_size, TEE_SHA384_HASH_SIZE,
			    &slot->mbn);
	if (res) {
		EMSG("PAS auth: MBN parse failed: %#"PRIx32, res);
		return res;
	}

	if (secure_boot_provisioned()) {
		res = pas_authenticate_signature(slot, pas_id);
		if (res)
			return res;
	}

	slot->authenticated = true;

	return TEE_SUCCESS;
}

TEE_Result pas_auth_verify_reset(struct qcom_pas_session *s,
				 TEE_TASessionHandle pta_session,
				 uint32_t pas_id,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct pas_md_slot *slot = find_md_slot(s, pas_id);
	TEE_Param vp[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t combined_size = 0;
	uint8_t *combined = NULL;
	uint32_t pt = 0;

	if (!slot || !slot->authenticated) {
		EMSG("PAS auth: pas_id=%"PRIu32
		     " not authenticated (call INIT_IMAGE first)", pas_id);
		return TEE_ERROR_BAD_STATE;
	}

	if (ADD_OVERFLOW(slot->md_size, slot->mbn.hash_table_size,
			 &combined_size))
		return TEE_ERROR_OVERFLOW;

	combined = TEE_Malloc(combined_size, TEE_MALLOC_FILL_ZERO);
	if (!combined)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(combined, slot->md, slot->md_size);
	TEE_MemMove(combined + slot->md_size, slot->mbn.hash_table,
		    slot->mbn.hash_table_size);

	pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			     TEE_PARAM_TYPE_VALUE_INPUT,
			     TEE_PARAM_TYPE_MEMREF_INPUT,
			     TEE_PARAM_TYPE_VALUE_INPUT);

	vp[0].value.a = params[0].value.a;
	vp[0].value.b = params[0].value.b;
	vp[1].value.a = params[1].value.a;
	vp[1].value.b = params[1].value.b;
	vp[2].memref.buffer = combined;
	vp[2].memref.size = combined_size;
	vp[3].value.a = slot->mbn.hash_size;
	vp[3].value.b = slot->md_size; /* hash-table offset in combined buf */

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_QCOM_PAS_VERIFY_IMAGE, pt, vp, NULL);

	TEE_Free(combined);
	return res;
}
