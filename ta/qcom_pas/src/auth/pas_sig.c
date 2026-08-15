// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_sig.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>
#include <utee_defines.h>

#define DER_SEQUENCE_TAG \
	(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)

static TEE_Result md_from_tee(uint32_t hash_algo, mbedtls_md_type_t *md)
{
	switch (hash_algo) {
	case TEE_ALG_SHA256:
		*md = MBEDTLS_MD_SHA256;
		return TEE_SUCCESS;
	case TEE_ALG_SHA384:
		*md = MBEDTLS_MD_SHA384;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result digest(uint32_t hash_algo, const uint8_t *msg, size_t msg_len,
			 uint8_t *out, size_t *out_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_AllocateOperation(&op, hash_algo, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, msg, msg_len, out, out_len);

	TEE_FreeOperation(op);

	return res;
}

static const mbedtls_x509_crt_profile pas_crt_profile = {
	.allowed_mds = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
		       MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384),
	.allowed_pks = MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA) |
		       MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECKEY),
	.allowed_curves = MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1),
};

/* mbedTLS treats an absent EKU extension as unrestricted; require it. */
static TEE_Result check_eku(const mbedtls_x509_crt *leaf, bool enforced)
{
	size_t oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING);
	int ext = MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE;

	if (!enforced)
		return TEE_SUCCESS;

	if (!mbedtls_x509_crt_has_ext_type(leaf, ext)) {
		EMSG("PAS auth: leaf cert has no EKU extension");
		return TEE_ERROR_SECURITY;
	}

	if (mbedtls_x509_crt_check_extended_key_usage(leaf,
						      MBEDTLS_OID_CODE_SIGNING,
						      oid_len)) {
		EMSG("PAS auth: leaf cert missing code-signing EKU");
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

/* mbedTLS treats an absent KeyUsage extension as unrestricted; require it. */
static TEE_Result check_chain_constraints(const mbedtls_x509_crt *leaf,
					  bool eku_enforced)
{
	uint32_t ku = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
	const mbedtls_x509_crt *crt = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t depth = 0;

	if (!mbedtls_x509_crt_has_ext_type(leaf, MBEDTLS_X509_EXT_KEY_USAGE)) {
		EMSG("PAS auth: leaf cert has no KeyUsage extension");
		return TEE_ERROR_SECURITY;
	}

	if (mbedtls_x509_crt_check_key_usage(leaf, ku)) {
		EMSG("PAS auth: leaf cert missing digitalSignature KeyUsage");
		return TEE_ERROR_SECURITY;
	}

	res = check_eku(leaf, eku_enforced);
	if (res)
		return res;

	for (crt = leaf; crt; crt = crt->next, depth++) {
		int ca = mbedtls_x509_crt_get_ca_istrue(crt);

		if (ca < 0) {
			EMSG("PAS auth: cannot read CA flag at depth %zu",
			     depth);
			return TEE_ERROR_SECURITY;
		}

		if (crt == leaf) {
			if (ca) {
				EMSG("PAS auth: leaf cert asserts CA");
				return TEE_ERROR_SECURITY;
			}
			continue;
		}

		if (!ca) {
			EMSG("PAS auth: issuer at depth %zu is not a CA",
			     depth);
			return TEE_ERROR_SECURITY;
		}
	}

	return TEE_SUCCESS;
}

static bool asn1_buf_eq(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
	return a->len && a->len == b->len && !memcmp(a->p, b->p, a->len);
}

static TEE_Result check_issuer_linkage(const mbedtls_x509_crt *issuer,
				       const mbedtls_x509_crt *subject)
{
	const mbedtls_x509_authority *akid = &subject->authority_key_id;

	if (akid->keyIdentifier.len &&
	    issuer->subject_key_id.len &&
	    !asn1_buf_eq(&akid->keyIdentifier, &issuer->subject_key_id)) {
		EMSG("PAS auth: AKID/SKID mismatch in cert chain");
		return TEE_ERROR_SECURITY;
	}

	if (akid->authorityCertSerialNumber.len &&
	    !asn1_buf_eq(&akid->authorityCertSerialNumber, &issuer->serial)) {
		EMSG("PAS auth: AKID serial mismatch in cert chain");
		return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

/* mbedTLS's cert profile can't express exact algo pairings; gate them here. */
static TEE_Result check_sig_algo(const mbedtls_x509_crt *crt,
				 mbedtls_pk_type_t *pk_out,
				 mbedtls_md_type_t *md_out)
{
	mbedtls_pk_type_t pk = MBEDTLS_PK_NONE;
	mbedtls_md_type_t md = MBEDTLS_MD_NONE;

	if (mbedtls_oid_get_sig_alg(&crt->sig_oid, &md, &pk))
		return TEE_ERROR_SECURITY;

	if (pk != MBEDTLS_PK_ECDSA || md != MBEDTLS_MD_SHA384)
		return TEE_ERROR_SECURITY;

	if (pk_out)
		*pk_out = pk;
	if (md_out)
		*md_out = md;

	return TEE_SUCCESS;
}

static TEE_Result check_chain_sig_algos(const mbedtls_x509_crt *leaf,
					size_t num_prefix)
{
	const mbedtls_x509_crt *crt = NULL;
	size_t i = 0;

	for (crt = leaf->next, i = 1; crt && i < num_prefix;
	     crt = crt->next, i++) {
		if (check_sig_algo(crt, NULL, NULL)) {
			EMSG("PAS auth: unsupported sig algo at depth %zu", i);
			return TEE_ERROR_SECURITY;
		}
	}

	return TEE_SUCCESS;
}

#define PAS_MIN_NUM_CERTS	2U
#define PAS_MAX_CERT_CHAIN_LEVEL 3U
#define PAS_MAX_NUM_ROOT_CERTS	4U
#define PAS_TOTAL_MAX_CERTS	(PAS_MAX_NUM_ROOT_CERTS + \
				 PAS_MAX_CERT_CHAIN_LEVEL - 1)

TEE_Result pas_sig_verify_cert_chain(const uint8_t *chain_der,
				     size_t chain_der_len, bool eku_enforced,
				     uint32_t num_roots,
				     uint32_t root_cert_sel,
				     const uint8_t **leaf_der,
				     size_t *leaf_der_len,
				     const uint8_t **roots_der,
				     size_t *roots_der_len)
{
	TEE_Result res = TEE_ERROR_SECURITY;
	const mbedtls_x509_crt *crt = NULL;
	mbedtls_x509_crt *sel_root = NULL;
	mbedtls_x509_crt *leaf = NULL;
	mbedtls_x509_crt chain = { };
	mbedtls_x509_crt trust = { };
	size_t num_prefix = 0;
	size_t sel_index = 0;
	size_t roots_off = 0;
	size_t num_certs = 0;
	uint32_t flags = 0;
	size_t off = 0;
	size_t i = 0;
	int rc = 0;

	if (!chain_der || !chain_der_len || !leaf_der || !leaf_der_len ||
	    !num_roots || num_roots > PAS_MAX_NUM_ROOT_CERTS ||
	    root_cert_sel >= num_roots)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_x509_crt_init(&chain);
	mbedtls_x509_crt_init(&trust);

	while (off < chain_der_len && chain_der[off] == DER_SEQUENCE_TAG) {
		mbedtls_x509_crt *added = NULL;

		if (num_certs >= PAS_TOTAL_MAX_CERTS)
			break;

		if (mbedtls_x509_crt_parse_der(&chain, chain_der + off,
					       chain_der_len - off)) {
			EMSG("PAS auth: cert %zu parse failed", num_certs);
			goto out;
		}

		added = &chain;
		while (added->next)
			added = added->next;

		off += added->raw.len;
		num_certs++;
	}

	for (i = off; i < chain_der_len; i++) {
		if (chain_der[i] != 0xFF) {
			EMSG("PAS auth: non-0xFF byte at chain offset %zu", i);
			goto out;
		}
	}

	if (num_certs <= num_roots) {
		EMSG("PAS auth: chain has %zu certs, need > %#"PRIx32" roots",
		     num_certs, num_roots);
		goto out;
	}
	num_prefix = num_certs - num_roots;
	if (num_prefix < (PAS_MIN_NUM_CERTS - 1) ||
	    num_prefix > (PAS_MAX_CERT_CHAIN_LEVEL - 1)) {
		EMSG("PAS auth: chain has %zu non-root certs, want [%u, %u]",
		     num_prefix, PAS_MIN_NUM_CERTS - 1,
		     PAS_MAX_CERT_CHAIN_LEVEL - 1);
		goto out;
	}

	leaf = &chain;

	sel_index = num_prefix + root_cert_sel;
	for (crt = &chain, i = 0; crt; crt = crt->next, i++) {
		if (i < num_prefix)
			roots_off += crt->raw.len;
		if (i == sel_index)
			sel_root = (mbedtls_x509_crt *)crt;
	}
	if (!sel_root) {
		EMSG("PAS auth: selected root %zu not present", sel_index);
		goto out;
	}

	if (mbedtls_x509_crt_parse_der(&trust, sel_root->raw.p,
				       sel_root->raw.len)) {
		EMSG("PAS auth: root cert re-parse failed");
		goto out;
	}

	rc = mbedtls_x509_crt_verify_with_profile(leaf, &trust, NULL,
						  &pas_crt_profile, NULL,
						  &flags, NULL, NULL);
	/*
	 * No trusted time: tolerate a failure whose only cause is an
	 * expired/future cert. A zero flags with a nonzero rc means
	 * verification did not run to completion for an unrelated reason
	 * (e.g. a parse or allocation failure), which must still be fatal.
	 */
	if (rc && (!flags ||
		   (flags & ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
					 MBEDTLS_X509_BADCERT_FUTURE)))) {
		EMSG("PAS auth: cert chain verify failed (%#"PRIx32")", flags);
		goto out;
	}

	res = check_chain_constraints(leaf, eku_enforced);
	if (res)
		goto out;

	res = check_chain_sig_algos(leaf, num_prefix);
	if (res)
		goto out;

	crt = leaf;
	for (i = 0; i + 1 < num_prefix; i++) {
		res = check_issuer_linkage(crt->next, crt);
		if (res)
			goto out;
		crt = crt->next;
	}
	res = check_issuer_linkage(sel_root, crt);
	if (res)
		goto out;

	if (roots_off > off || off > chain_der_len ||
	    leaf->raw.len > chain_der_len) {
		EMSG("PAS auth: cert DER length exceeds chain buffer");
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	*leaf_der = chain_der;
	*leaf_der_len = leaf->raw.len;
	if (roots_der)
		*roots_der = chain_der + roots_off;
	if (roots_der_len)
		*roots_der_len = off - roots_off;

	res = TEE_SUCCESS;
out:
	mbedtls_x509_crt_free(&trust);
	mbedtls_x509_crt_free(&chain);

	return res;
}

static TEE_Result pas_sig_verify_hash(uint32_t hash_algo,
				      const uint8_t *data, size_t data_len,
				      const uint8_t *expected,
				      size_t hash_len)
{
	uint8_t digest[PAS_SIG_MAX_HASH_SIZE] = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t len = sizeof(digest);

	if (!data || !expected || !hash_len || hash_len > sizeof(digest))
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, hash_algo, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, data, data_len, digest, &len);
	if (res != TEE_SUCCESS)
		goto out;

	if (len != hash_len) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	if (consttime_memcmp(digest, expected, hash_len) != 0)
		res = TEE_ERROR_SECURITY;
	else
		res = TEE_SUCCESS;
out:
	TEE_FreeOperation(op);
	memzero_explicit(digest, sizeof(digest));

	return res;
}

TEE_Result pas_sig_check_root_of_trust(uint32_t rot_hash_algo,
				       size_t rot_hash_len,
				       const uint8_t *root_der,
				       size_t root_der_len,
				       const uint8_t *expected)
{
	if (!root_der || !root_der_len || !expected)
		return TEE_ERROR_BAD_PARAMETERS;

	return pas_sig_verify_hash(rot_hash_algo, root_der, root_der_len,
				   expected, rot_hash_len);
}

TEE_Result pas_sig_algo_from_leaf(const uint8_t *leaf_der,
				  size_t leaf_der_len, uint32_t *sig_algo,
				  uint32_t *sig_hash_algo)
{
	mbedtls_pk_type_t pk = MBEDTLS_PK_NONE;
	mbedtls_md_type_t md = MBEDTLS_MD_NONE;
	TEE_Result res = TEE_ERROR_SECURITY;
	mbedtls_x509_crt leaf = { };

	if (!leaf_der || !leaf_der_len || !sig_algo || !sig_hash_algo)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_x509_crt_init(&leaf);
	if (mbedtls_x509_crt_parse_der(&leaf, leaf_der, leaf_der_len)) {
		EMSG("PAS auth: leaf cert parse failed");
		goto out;
	}

	res = check_sig_algo(&leaf, &pk, &md);
	if (res) {
		EMSG("PAS auth: leaf signatureAlgorithm not accepted");
		goto out;
	}

	switch (pk) {
	case MBEDTLS_PK_ECDSA:
		*sig_hash_algo = TEE_ALG_SHA384;
		*sig_algo = TEE_ALG_ECDSA_SHA384;
		break;
	default:
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	res = TEE_SUCCESS;
out:
	mbedtls_x509_crt_free(&leaf);

	return res;
}

/* mbedTLS rejects trailing padding; derive the true DER length here. */
static size_t ecdsa_der_sig_len(const uint8_t *sig, size_t field_len)
{
	size_t len = 0;

	if (field_len < 2 || sig[0] != DER_SEQUENCE_TAG)
		return field_len;

	if (sig[1] < 0x80)
		len = (size_t)sig[1] + 2;
	else if (sig[1] == 0x81 && field_len >= 3)
		len = (size_t)sig[2] + 3;
	else
		return field_len;

	return len <= field_len ? len : field_len;
}

TEE_Result pas_sig_verify_signature(uint32_t sig_algo,
				    uint32_t sig_hash_algo,
				    const uint8_t *leaf_der,
				    size_t leaf_der_len,
				    const uint8_t *msg, size_t msg_len,
				    const uint8_t *sig, size_t sig_len)
{
	uint8_t digest_buf[PAS_SIG_MAX_HASH_SIZE] = { };
	size_t digest_buf_len = sizeof(digest_buf);
	mbedtls_md_type_t md = MBEDTLS_MD_NONE;
	TEE_Result res = TEE_ERROR_SECURITY;
	mbedtls_x509_crt leaf = { };
	size_t actual_sig_len = 0;
	int rc = 0;

	if (!leaf_der || !leaf_der_len || !msg || !msg_len || !sig || !sig_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (sig_len > PAS_SIG_MAX_SIG_SIZE)
		return TEE_ERROR_SECURITY;

	res = md_from_tee(sig_hash_algo, &md);
	if (res != TEE_SUCCESS)
		return res;

	res = digest(sig_hash_algo, msg, msg_len, digest_buf, &digest_buf_len);
	if (res != TEE_SUCCESS)
		return res;

	mbedtls_x509_crt_init(&leaf);
	if (mbedtls_x509_crt_parse_der(&leaf, leaf_der, leaf_der_len)) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	switch (sig_algo) {
	case TEE_ALG_ECDSA_SHA384:
		actual_sig_len = ecdsa_der_sig_len(sig, sig_len);
		rc = mbedtls_pk_verify(&leaf.pk, md, digest_buf, digest_buf_len,
				       sig, actual_sig_len);
		break;
	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	if (rc) {
		EMSG("PAS auth: signature verify failed (%d)", rc);
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	res = TEE_SUCCESS;
out:
	mbedtls_x509_crt_free(&leaf);
	memzero_explicit(digest_buf, sizeof(digest_buf));

	return res;
}
