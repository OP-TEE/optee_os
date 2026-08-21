// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <auth/pas_fuse.h>
#include <auth/pas_mbn.h>
#include <auth/pas_meta.h>
#include <auth/pas_policy.h>
#include <auth/pas_sig.h>
#include <auth/pas_sig_auth.h>
#include <pta_qcom_fuse.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <utee_defines.h>
#include <util.h>

#define SECBOOT_METADATA_MAJOR_V0	0U
#define SECBOOT_METADATA_MAJOR_V1	1U
#define SECBOOT_METADATA_MINOR		0U
#define SECBOOT_DEFAULT_ROOT_CERT_SEL	0U

static TEE_Result check_metadata_version(const struct pas_oem_metadata *meta)
{
	if ((meta->major == SECBOOT_METADATA_MAJOR_V0 ||
	     meta->major == SECBOOT_METADATA_MAJOR_V1) &&
	    meta->minor == SECBOOT_METADATA_MINOR)
		return TEE_SUCCESS;

	EMSG("PAS auth: unsupported metadata version %#"PRIx32".%#"PRIx32,
	     meta->major, meta->minor);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_sw_binding(const struct pas_oem_metadata *meta,
				   uint32_t pas_id)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t expected = 0;

	res = pas_policy_expected_swid(pas_id, &expected);
	if (res) {
		EMSG("PAS auth: no SW_ID binding for pas_id %#"PRIx32, pas_id);
		return res;
	}

	if (meta->sw_id != expected) {
		EMSG("PAS auth: SW_ID got %#"PRIx32" want %#"PRIx32,
		     meta->sw_id, expected);
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static uint32_t pas_meta_option(uint32_t flags, uint32_t shift)
{
	return (flags >> shift) & PAS_META_OPTION_MASK;
}

static bool pas_meta_option_sn_gated(uint32_t flags, uint32_t shift)
{
	return pas_meta_option(flags, shift) == PAS_META_OPTION_ENABLE_SN;
}

static TEE_Result check_metadata_options(const struct pas_oem_metadata *meta)
{
	if (pas_meta_option(meta->flags,
			    PAS_META_FLAG_ROOT_REVOKE_ACTIVATE_SHIFT) <=
	    PAS_META_OPTION_MAX &&
	    pas_meta_option(meta->flags, PAS_META_FLAG_UIE_KEY_SWITCH_SHIFT) <=
	    PAS_META_OPTION_MAX &&
	    pas_meta_option(meta->flags, PAS_META_FLAG_DEBUG_SHIFT) <=
	    PAS_META_OPTION_MAX)
		return TEE_SUCCESS;

	EMSG("PAS auth: reserved metadata option value, flags=%#"PRIx32,
	     meta->flags);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_oem_model_binding(const struct pas_oem_metadata *meta,
					  const struct pas_device_ids *ids)
{
	bool oem_independent = meta->flags &
				BIT32(PAS_META_FLAG_OEM_ID_INDEPENDENT);
	bool model_independent = false;

	/* v0 metadata has no MODEL_ID_INDEPENDENT bit; falls back to OEM's. */
	if (meta->major == 0)
		model_independent = oem_independent;
	else
		model_independent = meta->flags &
				    BIT32(PAS_META_FLAG_MODEL_ID_INDEPENDENT);

	if (!oem_independent && meta->oem_id != ids->oem_id) {
		EMSG("PAS auth: OEM_ID got %#"PRIx32" want %#"PRIx32,
		     meta->oem_id, ids->oem_id);
		return TEE_ERROR_SECURITY;
	}

	if (!model_independent && meta->model_id != ids->model_id) {
		EMSG("PAS auth: MODEL_ID got %#"PRIx32" want %#"PRIx32,
		     meta->model_id, ids->model_id);
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result check_jtag_binding(const struct pas_oem_metadata *meta,
				     const struct pas_device_ids *ids)
{
	if (!(meta->flags & BIT32(PAS_META_FLAG_IN_USE_JTAG_ID)))
		return TEE_SUCCESS;

	if (meta->hw_id == ids->jtag_id)
		return TEE_SUCCESS;

	EMSG("PAS auth: HW_ID got %#"PRIx32" want %#"PRIx32, meta->hw_id,
	     ids->jtag_id);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_serial_binding(const struct pas_oem_metadata *meta,
				       const struct pas_device_ids *ids,
				       bool use_serial_num_override)
{
	static const uint32_t sn_gated_shifts[] = {
		PAS_META_FLAG_DEBUG_SHIFT,
		PAS_META_FLAG_ROOT_REVOKE_ACTIVATE_SHIFT,
		PAS_META_FLAG_UIE_KEY_SWITCH_SHIFT,
	};
	bool sn_gated = false;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(sn_gated_shifts); i++) {
		if (pas_meta_option_sn_gated(meta->flags, sn_gated_shifts[i])) {
			sn_gated = true;
			break;
		}
	}

	if (!(meta->flags & BIT32(PAS_META_FLAG_USE_SERIAL_NUMBER)) &&
	    !use_serial_num_override && !sn_gated)
		return TEE_SUCCESS;

	if (!ids->serial_num) {
		EMSG("PAS auth: serial binding required, no fused serial");
		return TEE_ERROR_SECURITY;
	}

	for (i = 0; i < ARRAY_SIZE(meta->serial_num); i++) {
		if (meta->serial_num[i] &&
		    meta->serial_num[i] == ids->serial_num)
			return TEE_SUCCESS;
	}

	EMSG("PAS auth: serial number %#"PRIx32" not in metadata allow-list",
	     ids->serial_num);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_soc_vers_binding(const struct pas_oem_metadata *meta,
					 uint32_t fam_dev)
{
	size_t i = 0;

	if (!(meta->flags & BIT32(PAS_META_FLAG_IN_USE_SOC_HW_VERSION)))
		return TEE_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(meta->soc_vers); i++) {
		if (meta->soc_vers[i] == fam_dev)
			return TEE_SUCCESS;
	}

	EMSG("PAS auth: SOC_HW_VERSION %#"PRIx32" not in metadata allow-list",
	     fam_dev);
	return TEE_ERROR_SECURITY;
}

static TEE_Result check_hw_binding(const struct pas_oem_metadata *meta)
{
	struct pas_fuse_hw_binding_info info = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	bool need_soc_vers = false;

	res = check_metadata_options(meta);
	if (res)
		return res;

	need_soc_vers = meta->flags &
			BIT32(PAS_META_FLAG_IN_USE_SOC_HW_VERSION);
	res = pas_fuse_get_hw_binding_info(need_soc_vers, &info);
	if (res)
		return res;

	res = check_oem_model_binding(meta, &info.ids);
	if (res)
		return res;

	res = check_jtag_binding(meta, &info.ids);
	if (res)
		return res;

	res = check_serial_binding(meta, &info.ids,
				   info.use_serial_num_override);
	if (res)
		return res;

	res = check_soc_vers_binding(meta, info.soc_fam_dev);
	if (res)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result reject_if_encrypted(const struct pas_mbn *hs)
{
	if (!hs->uie_encrypted)
		return TEE_SUCCESS;

	EMSG("PAS auth: UIE image encryption not supported");

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result reject_if_double_signed(const struct pas_mbn *hs)
{
	if (hs->qti_certs || hs->qti_sig) {
		EMSG("PAS auth: QTI-countersigned images are not supported");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result verify_authenticity(const struct pas_mbn *hs,
				      uint32_t pas_id,
				      const uint8_t *anchor)
{
	uint32_t rot_hash_algo = TEE_ALG_SHA384;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pas_oem_metadata meta = { };
	uint8_t *signed_copy = NULL;
	const uint8_t *roots = NULL;
	uint32_t sig_hash_algo = 0;
	const uint8_t *leaf = NULL;
	bool eku_enforced = false;
	uint32_t sig_algo = 0;
	size_t signed_len = 0;
	size_t roots_len = 0;
	size_t leaf_len = 0;

	if (!hs->oem_certs || !hs->oem_sig || !hs->signed_region) {
		EMSG("PAS auth: metadata is not OEM-signed");
		return TEE_ERROR_SECURITY;
	}

	res = pas_fuse_get_eku_enforcement_en(&eku_enforced);
	if (res) {
		EMSG("PAS auth: cannot read EKU enforcement fuse: %#"PRIx32,
		     res);
		return res;
	}

	res = pas_sig_verify_cert_chain(hs->oem_certs, hs->oem_certs_size,
					eku_enforced, 1,
					SECBOOT_DEFAULT_ROOT_CERT_SEL, &leaf,
					&leaf_len, &roots, &roots_len);
	if (res) {
		EMSG("PAS auth: OEM cert chain invalid: %#"PRIx32, res);
		return res;
	}

	res = pas_sig_check_root_of_trust(rot_hash_algo,
					  PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE,
					  roots, roots_len, anchor);
	if (res) {
		EMSG("PAS auth: root-of-trust mismatch");
		return res;
	}

	res = pas_meta_get(hs, &meta);
	if (res == TEE_ERROR_NO_DATA)
		res = TEE_ERROR_SECURITY;
	if (res) {
		EMSG("PAS auth: bad or missing OEM metadata");
		return res;
	}

	res = check_metadata_version(&meta);
	if (res)
		return res;

	res = check_sw_binding(&meta, pas_id);
	if (res)
		return res;

	res = check_hw_binding(&meta);
	if (res)
		return res;

	res = pas_sig_algo_from_leaf(leaf, leaf_len, &sig_algo,
				     &sig_hash_algo);
	if (res) {
		EMSG("PAS auth: cannot determine signature algorithm: %#"PRIx32,
		     res);
		return res;
	}

	res = pas_meta_get_signed_region_copy(hs, &signed_copy, &signed_len);
	if (res)
		return res;

	res = pas_sig_verify_signature(sig_algo, sig_hash_algo, leaf,
				       leaf_len, signed_copy, signed_len,
				       hs->oem_sig, hs->oem_sig_size);
	TEE_Free(signed_copy);
	if (res) {
		EMSG("PAS auth: OEM signature verify failed: %#"PRIx32, res);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_sig_auth_segment_hash_len(const struct pas_md_slot *slot,
					 uint32_t *segment_hash_len)
{
	uint32_t root_cert_sel = SECBOOT_DEFAULT_ROOT_CERT_SEL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = pas_meta_get_root_cert_sel(slot->meta_data,
					 slot->meta_data_size,
					 &root_cert_sel);
	if (res == TEE_ERROR_NO_DATA)
		root_cert_sel = SECBOOT_DEFAULT_ROOT_CERT_SEL;
	else if (res)
		return res;

	res = pas_fuse_get_segment_hash_len(root_cert_sel, segment_hash_len);
	if (res) {
		EMSG("PAS auth: segment hash size read failed: %#"PRIx32, res);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_sig_auth_verify_image(const struct pas_mbn *hs,
				     const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t pas_id,
				     uint32_t segment_hash_len,
				     const uint8_t *anchor)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = reject_if_encrypted(hs);
	if (res)
		return res;

	res = reject_if_double_signed(hs);
	if (res)
		return res;

	res = verify_authenticity(hs, pas_id, anchor);
	if (res)
		return res;

	res = pas_meta_verify_preamble(meta_data, meta_data_size,
				       hs->hash_table, segment_hash_len);
	if (res)
		return res;

	return TEE_SUCCESS;
}
