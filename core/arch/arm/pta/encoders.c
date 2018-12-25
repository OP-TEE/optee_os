/*
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* File contains functions, which provide general encoding for Internet X.509
 * Public Key Infrastructure Certificate.
 */
#include "x509_attestation.h"

/* attestation extensions values */
const unsigned char attestKeyUsageSign[] = {0x03, 0x02, 0x07, 0x80};
const unsigned char attestKeyUsageEncr[] = {0x03, 0x02, 0x04, 0x30};
const unsigned char attestKeyUsageZero[] = {0x03, 0x02, 0x08, 0x00};
const unsigned char attestKeyUsageAll[]  = {0x03, 0x02, 0x04, 0xB0};

/* contains der-encoded sha1 hash from public key */
unsigned char SubjKeyId[SUBJ_KEY_ID_SIZE];

/* SHA256 hash of the verified boot key */
const unsigned char verifiedBootKey[SHA256_BUFFER_SIZE] = {
		0x77, 0x28, 0xE3, 0x0F, 0x50, 0xBF, 0xA5, 0xCE, 0xA1, 0x65,
		0xF4, 0x73, 0x17, 0x5A, 0x08, 0x80, 0x3F, 0x6A, 0x83, 0x46,
		0x64, 0x2B, 0x5A, 0xA1, 0x09, 0x13, 0xE9, 0xD9, 0xE6, 0xDE,
		0xFE, 0xF6
};

static ltc_asn1_list sw_purpose[KEY_PURPOSE_SIZE];
static ltc_asn1_list sw_digest[KEY_DIGEST_SIZE];
static ltc_asn1_list sw_padding[KEY_PADDING_SIZE];

static ltc_asn1_list hw_purpose[KEY_PURPOSE_SIZE];
static ltc_asn1_list hw_digest[KEY_DIGEST_SIZE];
static ltc_asn1_list hw_padding[KEY_PADDING_SIZE];

static ULONG sw_prps_size;
static ULONG sw_dgst_size;
static ULONG sw_pdng_size;

static ULONG hw_prps_size;
static ULONG hw_dgst_size;
static ULONG hw_pdng_size;

static const unsigned long attestationTags[] = {
		1, 2, 3, 5, 6, 10, 200, 400, 401, 402, 503, 504, 505, 506, 600,
		601, 701, 702, 703, 704, 705, 706,
		/* KM 3 */
		709, 710, 711, 712, 713, 714, 715, 716, 717
};

/* ========== OID encoders ========== */

/* Encode Algorithm Identifier to sequence in der_algId */
static void encodeSimpleAlgID(der_algId *algId, ULONG const *alg_oid,
			      const ULONG size, const int rsa)
{
	LTC_SET_ASN1((ltc_asn1_list *)algId, 0, LTC_ASN1_OBJECT_IDENTIFIER,
				 (void *)alg_oid, size);
	if (rsa)
		LTC_SET_ASN1((ltc_asn1_list *)algId, 1, LTC_ASN1_NULL, NULL, 0);
	else
		LTC_SET_ASN1((ltc_asn1_list *)algId, 1, LTC_ASN1_EOL, NULL, 0);
}

/* Encode Algorithm Identifier from oidStruct for RSA */
void encodeAlgOidRSA(der_algId *algId, const OidStruct *oid)
{
	encodeSimpleAlgID(algId, oid->oid, oid->oid_size, 1);
}

/* Encode Algorithm Identifier from oidStruct for ECC */
void encodeAlgOidECC(der_algId *algId, const OidStruct *oid)
{
	encodeSimpleAlgID(algId, oid->oid, oid->oid_size, 0);
}

/* Encode Algorithm Identifier from oidStruct for ECC SubjectPublicKeyInfo */
void encodeAlgOidECC_SPK(der_algId *algId, const OidStruct *oid)
{
	LTC_SET_ASN1((ltc_asn1_list *)algId, 0, LTC_ASN1_OBJECT_IDENTIFIER,
		     (void *)oid->oid, oid->oid_size);
	LTC_SET_ASN1((ltc_asn1_list *)algId, 1, LTC_ASN1_OBJECT_IDENTIFIER,
		     (void *)(oid + 1)->oid, (oid + 1)->oid_size);
}

/* ========== RDN name encoders ========== */

/* Encode oid and printable string to sequence for der_oidName */
static void encodeName(der_oidName *cn, ULONG const *cn_oid, const ULONG size,
		       const char *cn_name)
{
	LTC_SET_ASN1(&cn->arrName[0], 0, LTC_ASN1_OBJECT_IDENTIFIER,
		     (void *)cn_oid, size);
	LTC_SET_ASN1(&cn->arrName[0], 1, LTC_ASN1_PRINTABLE_STRING,
		     (void *)cn_name, strlen(cn_name));

	LTC_SET_ASN1(&cn->sequence, 0, LTC_ASN1_SEQUENCE, (void *)cn->arrName,
		     NAME_SIZE);
}

/* Encode SampleNames array to array with DER-encoded sequences */
void encodeSampleNames(der_oidName *cn, SampleName *sn, ULONG size)
{
	ULONG i;

	for (i = 0; i < size; ++i)
		encodeName(cn + i, ((sn + i)->oidSt).oid,
			   ((sn + i)->oidSt).oid_size, (sn + i)->name);
}

/* Encode DER-encoded array of sequences to final RDN-sequence */
static void derEncodeNames(ltc_asn1_list *name, der_oidName *derNames, int size)
{
	int i;

	for (i = 0; i < size; ++i)
		LTC_SET_ASN1(name, i, LTC_ASN1_SET, &(derNames[i].sequence), 1);
}

/* Wrapper for DER-encoded sequences */
int encodeRDNName(ltc_asn1_list *name, der_oidName *derNames, ULONG size,
		  NameSetter nameSetter)
{
	int res;

	res = nameSetter(derNames, size);
	if (!res)
		derEncodeNames(name, derNames, size);

	return res;
}

/* ========== TAG wrappers ========== */

static void encodeTag(ltc_exp_tag *tag, const ULONG tag_val,
		      ltc_asn1_list *asnList, ltc_asn1_type type,
		      void *data, const ULONG data_size)
{
	tag->tag = tag_val;
	tag->list = asnList;

	LTC_SET_ASN1(asnList, 0, type, data, data_size);
}

/* Set TAG to short integer */
void encodeTagInt(ltc_exp_tag *tag, ltc_asn1_list *asnInt, const ULONG tag_val,
		  ULONG *int_val)
{
	encodeTag(tag, tag_val, asnInt, LTC_ASN1_SHORT_INTEGER, int_val, 1);
}

/* Set TAG to long integer */
void encodeTagLong(ltc_exp_tag *tag, ltc_asn1_list *asnInt, const ULONG tag_val,
		   ULONG *int_val)
{
	encodeTag(tag, tag_val, asnInt, LTC_ASN1_LONG_INTEGER, int_val, 1);
}

/* Set TAG to SEQUENCE */
void encodeTagSeq(ltc_exp_tag *tag, ltc_asn1_list *asnSeq, const ULONG tag_val,
		  void *sequence, const ULONG seq_size)
{
	encodeTag(tag, tag_val, asnSeq, LTC_ASN1_SEQUENCE, sequence, seq_size);
}

/* Set TAG to SETOF */
void encodeTagSetof(ltc_exp_tag *tag, ltc_asn1_list *asnSetof,
		    const ULONG tag_val, void *setof,
		    const ULONG setof_size)
{
	encodeTag(tag, tag_val, asnSetof, LTC_ASN1_SETOF, setof, setof_size);
}

/* Set TAG to NULL */
void encodeTagNul(ltc_exp_tag *tag, ltc_asn1_list *asnNull, const ULONG tag_val)
{
	encodeTag(tag, tag_val, asnNull, LTC_ASN1_NULL, NULL, 0);
}

/* Set TAG to OCTET_STRING */
void encodeTagOctetString(ltc_exp_tag *tag, ltc_asn1_list *asnOctStr,
			  const ULONG tag_val, void *string,
			  const ULONG str_size)
{
	encodeTag(tag, tag_val, asnOctStr, LTC_ASN1_OCTET_STRING, string,
		  str_size);
}

/* ========== Time encoders ========== */

/* Hardcoded start time: 00:00:00, 1 Jan, 2018 */
static void hardcodeStartTime(ltc_utctime *derTime)
{
	if (!derTime)
		return;

	derTime->ss = 0;
	derTime->mm = 0;
	derTime->hh = 0;
	derTime->MM = 1;
	derTime->DD = 1;
	derTime->YY = 18;
	derTime->off_dir = 0;
	derTime->off_hh = 0;
	derTime->off_mm = 0;
}

/* Hardcoded end time: 00:00:00, 1 Jan, 2021 */
static void hardcodeEndTime(ltc_utctime *derTime)
{
	if (!derTime)
		return;

	derTime->ss = 0;
	derTime->mm = 0;
	derTime->hh = 0;
	derTime->MM = 1;
	derTime->DD = 1;
	derTime->YY = 21;
	derTime->off_dir = 0;
	derTime->off_hh = 0;
	derTime->off_mm = 0;
}

void encodeHardcodedValidity(der_Validity *validity)
{
	hardcodeStartTime(&validity->notBefore);
	hardcodeEndTime(&validity->notAfter);

	LTC_SET_ASN1(validity->arr, 0, LTC_ASN1_UTCTIME,
		     (void *)&validity->notBefore, 1);
	LTC_SET_ASN1(validity->arr, 1, LTC_ASN1_UTCTIME,
		     (void *)&validity->notAfter, 1);

	LTC_SET_ASN1(&validity->sequence, 0, LTC_ASN1_SEQUENCE,
		     (void *)validity->arr, 2);
}

/* ========== Subject publid key info encoders ========== */

static int createBigNum(void **bn, const void *num, const ULONG size)
{
	int res;

	res = ltc_mp.init(bn);
	if (res != CRYPT_OK)
		return res;

	res = ltc_mp.unsigned_read(*bn, (unsigned char *)num, size);
	return res;
}

int encodeSubPubKeyInfoRSA_BN(der_rsaKeyInfo *rsaKeyInfo,
			      const void *modulus, const void *exp,
			      unsigned char **pk, ULONG *pk_size)
{
	*pk_size = 0;
	*pk = NULL;

	rsaAlgIdEncode(&rsaKeyInfo->algId);

	LTC_SET_ASN1(rsaKeyInfo->arr, 0, LTC_ASN1_INTEGER, modulus, 1);
	LTC_SET_ASN1(rsaKeyInfo->arr, 1, LTC_ASN1_INTEGER, exp, 1);

	der_length_sequence(rsaKeyInfo->arr, RSA_PUB_KEY_SIZE, pk_size);

	*pk = malloc(*pk_size);

	if (!(*pk))
		return 1;

	der_encode_sequence(rsaKeyInfo->arr, RSA_PUB_KEY_SIZE, *pk, pk_size);

	LTC_SET_ASN1(rsaKeyInfo->seqArr, 0, X509_ALGID, &(rsaKeyInfo->algId),
		     ALG_ID_SIZE);
	LTC_SET_ASN1(rsaKeyInfo->seqArr, 1, LTC_ASN1_RAW_BIT_STRING, *pk,
		     8 * (*pk_size));

	return 0;
}

int encodeSubPubKeyInfoECC_BN(der_eccKeyInfo *eccKeyInfo, uint32_t curve,
			      void *x, void *y,
			      unsigned char **pk, ULONG *pk_size)
{
	int res;
	*pk_size = 0;
	*pk = NULL;

	eccAlgIdEncode(&eccKeyInfo->algId, curve);

	/* counting size of PK = size(x) + size(y) + 1 */
	*pk_size = ltc_mp.unsigned_size(x) + ltc_mp.unsigned_size(y) + 1;
	*pk = malloc(*pk_size);

	if (!(*pk))
		return 1;

	/* Firs byte of octet PK is 0x04 (SEC 1: Elliptic Curve Cryptography) */
	(*pk)[0] = 0x04;
	res = ltc_mp.unsigned_write(x, (*pk) + 1);
	if (res != CRYPT_OK)
		return res;

	res = ltc_mp.unsigned_write(y, (*pk) + 1 + ltc_mp.unsigned_size(x));
	if (res != CRYPT_OK)
		return res;

	LTC_SET_ASN1(eccKeyInfo->seqArr, 0, X509_ALGID, &(eccKeyInfo->algId),
		     ALG_ID_SIZE);
	LTC_SET_ASN1(eccKeyInfo->seqArr, 1, LTC_ASN1_RAW_BIT_STRING, *pk,
		     8 * (*pk_size));

	return 0;
}

int encodeSubPubKeyInfoRSA(der_rsaKeyInfo *rsaKeyInfo,
			   const unsigned char *modulus, const ULONG m_size,
			   const unsigned char *exp, const ULONG e_size,
			   unsigned char **pk, ULONG *pk_size)
{
	int res;
	void *m, *e;

	res = createBigNum(&m, modulus, m_size);
	if (res != CRYPT_OK)
		goto exit;
	res = createBigNum(&e, exp, e_size);
	if (res != CRYPT_OK)
		goto exit;

	res = encodeSubPubKeyInfoRSA_BN(rsaKeyInfo, m, e, pk, pk_size);

exit:
	/* free bignums */
	ltc_mp.deinit(m);
	ltc_mp.deinit(e);

	return res;
}

int encodeSubPubKeyInfoECC(der_eccKeyInfo *eccKeyInfo, uint32_t curve,
			   const unsigned char *x, const ULONG x_size,
			   const unsigned char *y, const ULONG y_size,
			   unsigned char **pk, ULONG *pk_size)
{
	int res;
	void *xv, *yv;

	res = createBigNum(&xv, x, x_size);
	if (res != CRYPT_OK)
		goto exit;
	res = createBigNum(&yv, y, y_size);
	if (res != CRYPT_OK)
		goto exit;

	res = encodeSubPubKeyInfoECC_BN(eccKeyInfo, curve, xv, yv, pk, pk_size);

exit:
	/* free bignums */
	ltc_mp.deinit(xv);
	ltc_mp.deinit(yv);

	return res;
}

/* ========== Extensions encoders ========== */

int encodeSubjKeyId(der_extValue *extVal, const unsigned char *pk,
		    const ULONG pk_size)
{
	int res = -1;
	unsigned char hash[SUBJ_KEY_ID_SIZE - 2]; /* sha1 hash size = 20*/
	ULONG outlen = SUBJ_KEY_ID_SIZE;

	hash_state md;

	if (find_hash_id(sha1_desc.ID) == -1)
		goto exit;

	res = sha1_init(&md);

	if (res != CRYPT_OK)
		goto exit;

	res = sha1_process(&md, pk, pk_size);
	if (res != CRYPT_OK)
		goto exit;

	res = sha1_done(&md, hash);
	if (res != CRYPT_OK)
		goto exit;

	res = der_encode_octet_string(hash, SUBJ_KEY_ID_SIZE - 2, SubjKeyId,
				      &outlen);

	if (res != CRYPT_OK || outlen != SUBJ_KEY_ID_SIZE) {
		res = -1;
		goto exit;
	}

	extVal->value = SubjKeyId;
	extVal->val_size = outlen;

exit:
	if (res != CRYPT_OK) {
		extVal->value = NULL;
		extVal->val_size = 0;
	}

	return res;
}

static void encodeExt(der_Extension *ext, ULONG const *ext_oid, const ULONG size,
		      const int *critical, const unsigned char *octet,
		      const ULONG octet_size)
{
	LTC_SET_ASN1((ltc_asn1_list *)ext, 0, LTC_ASN1_OBJECT_IDENTIFIER,
		     ext_oid, size);
	if (*critical) {
		LTC_SET_ASN1((ltc_asn1_list *)ext, 1, LTC_ASN1_BOOLEAN,
			     critical, 0);
		LTC_SET_ASN1((ltc_asn1_list *)ext, 2, LTC_ASN1_OCTET_STRING,
			     octet, octet_size);
	} else {
		LTC_SET_ASN1((ltc_asn1_list *)ext, 1, LTC_ASN1_OCTET_STRING,
			     octet, octet_size);
		LTC_SET_ASN1((ltc_asn1_list *)ext, 2, LTC_ASN1_EOL, NULL, 0);
	}
}

void encodeOneExtension(der_Extension *derExt, OneExtension *ext, ULONG size)
{
	ULONG i;

	for (i = 0; i < size; ++i)
		encodeExt(&derExt[i], ext[i].extOid.oid, ext[i].extOid.oid_size,
			  ext[i].critical, ext[i].extValue, ext[i].val_size);
}

/* Encode DER-encoded array of sequences to final extension sequence. */
static void derEncodeExtensions(ltc_asn1_list *all_extensions,
				der_Extension *der_extensions, int size)
{
	int i;

	for (i = 0; i < size; ++i)
		LTC_SET_ASN1(all_extensions, i, LTC_ASN1_SEQUENCE,
			     &(der_extensions[i]), SINGLE_EXT_SIZE);
}

/* Wrapper for DER-encoded sequences for extensions. */
int encodeExtensions(ltc_asn1_list *extensions, der_Extension *der_extensions,
		     der_extValue *values, ULONG size, ExtSetter extSetter)
{
	int res;

	res = extSetter(der_extensions, values, size);
	if (!res)
		derEncodeExtensions(extensions, der_extensions, size);

	return res;
}

/* ========== Attestation extensions encoders ========== */
static void fill_key_chars(keymaster_key_param_set_t *sw_key_chr,
			   keymaster_key_param_set_t *hw_key_chr,
			   der_extValue *keyUsage)
{
	size_t i;
	keymaster_purpose_t prps;
	uint8_t encr = 1;
	uint8_t sign = 2;
	uint8_t key_usage_flags = 0;

	for (i = 0; i < sw_key_chr->length; ++i) {
		switch (sw_key_chr->params[i].tag) {
		case KM_TAG_PURPOSE:
			LTC_SET_ASN1(sw_purpose, sw_prps_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(sw_key_chr->params[i].key_param.long_integer),
				     1);
			sw_prps_size++;
			prps = (keymaster_purpose_t)
				sw_key_chr->params[i].key_param.enumerated;
			switch (prps) {
			case KM_PURPOSE_ENCRYPT:
			case KM_PURPOSE_DECRYPT:
				key_usage_flags |= encr;
				break;
			case KM_PURPOSE_SIGN:
			case KM_PURPOSE_VERIFY:
				key_usage_flags |= sign;
				break;
			default:
				break;

			}
			break;
		case KM_TAG_DIGEST:
			LTC_SET_ASN1(sw_digest, sw_dgst_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(sw_key_chr->params[i].key_param.long_integer),
				     1);
			sw_dgst_size++;
			break;
		case KM_TAG_PADDING:
			LTC_SET_ASN1(sw_padding, sw_pdng_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(sw_key_chr->params[i].key_param.long_integer),
				     1);
			sw_pdng_size++;
			break;
		default:
			break;
		}
	}

	for (i = 0; i < hw_key_chr->length; ++i) {
		switch (hw_key_chr->params[i].tag) {
		case KM_TAG_PURPOSE:
			LTC_SET_ASN1(hw_purpose, hw_prps_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(hw_key_chr->params[i].key_param.long_integer),
				     1);
			hw_prps_size++;
			prps = (keymaster_purpose_t)
				hw_key_chr->params[i].key_param.enumerated;
			switch (prps) {
			case KM_PURPOSE_ENCRYPT:
			case KM_PURPOSE_DECRYPT:
				key_usage_flags |= encr;
				break;
			case KM_PURPOSE_SIGN:
			case KM_PURPOSE_VERIFY:
				key_usage_flags |= sign;
				break;
			default:
				break;

			}
			break;
		case KM_TAG_DIGEST:
			LTC_SET_ASN1(hw_digest, hw_dgst_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(hw_key_chr->params[i].key_param.long_integer),
				     1);
			hw_dgst_size++;
			break;
		case KM_TAG_PADDING:
			LTC_SET_ASN1(hw_padding, hw_pdng_size,
				     LTC_ASN1_SHORT_INTEGER,
				     &(hw_key_chr->params[i].key_param.long_integer),
				     1);
			hw_pdng_size++;
			break;
		default:
			break;
		}
	}

	if (key_usage_flags == encr) {
		keyUsage->value = (unsigned char *)attestKeyUsageEncr;
		keyUsage->val_size = COUNT(attestKeyUsageEncr);
	} else if (key_usage_flags == sign) {
		keyUsage->value = (unsigned char *)attestKeyUsageSign;
		keyUsage->val_size = COUNT(attestKeyUsageSign);
	} else if (key_usage_flags == (encr | sign)) {
		keyUsage->value = (unsigned char *)attestKeyUsageAll;
		keyUsage->val_size = COUNT(attestKeyUsageAll);
	} else {
		keyUsage->value = (unsigned char *)attestKeyUsageZero;
		keyUsage->val_size = COUNT(attestKeyUsageZero);
	}
}

static void set_chars(der_attestExtension *attest, int hw_flag,
		      keymaster_key_param_set_t *key_chr,
		      keymaster_key_param_set_t *params,
		      uint8_t verified_boot_state)
{
	size_t i, j;
	ltc_exp_tag *chars_tags;
	ltc_asn1_list *chars_list;
	ltc_asn1_list *final_list;
	ULONG *size;
	ULONG *_int;

	ltc_asn1_list *purpose;
	ULONG prps_size;

	ltc_asn1_list *digest;
	ULONG dgst_size;

	ltc_asn1_list *padding;
	ULONG pdng_size;

	if (hw_flag) {
		purpose = hw_purpose;
		digest = hw_digest;
		padding = hw_padding;
		prps_size = hw_prps_size;
		dgst_size = hw_dgst_size;
		pdng_size = hw_pdng_size;
		chars_tags = attest->hwEnforced;
		chars_list = attest->hwEnfList;
		final_list = attest->hw;
		size = &attest->hw_size;
	} else {
		purpose = sw_purpose;
		digest = sw_digest;
		padding = sw_padding;
		prps_size = sw_prps_size;
		dgst_size = sw_dgst_size;
		pdng_size = sw_pdng_size;
		chars_tags = attest->swEnforced;
		chars_list = attest->swEnfList;
		final_list = attest->sw;
		size = &attest->sw_size;
	}

	i = 0;
	*size = 0;
	/* setting KM_PURPOSE tag */
	if (prps_size > 0) {
		encodeTagSetof(&chars_tags[*size], &chars_list[*size],
			       attestationTags[i], purpose, prps_size);
		(*size)++;
	}

	/* setting KM_ALGORITHM and KM_KEY_SIZE tag */
	for (i = i + 1; i < 3; ++i) {
		for (j = 0; j < key_chr->length; ++j) {
			if (attestationTags[i] ==
				(key_chr->params[j].tag & 0x0FFFFFFF)) {
				_int = &(key_chr->params[j].key_param.long_integer);
				encodeTagInt(&chars_tags[*size],
					     &chars_list[*size],
					     attestationTags[i],
					     _int);
				(*size)++;
				break;
			}
		}
	}

	/* setting KM_DIGEST tag */
	if (dgst_size > 0) {
		encodeTagSetof(&chars_tags[*size], &chars_list[*size],
			       attestationTags[i], digest, dgst_size);
		(*size)++;
	}

	/* setting KM_PADDING tag */
	i++;
	if (pdng_size > 0) {
		encodeTagSetof(&chars_tags[*size], &chars_list[*size],
			       attestationTags[i], padding, pdng_size);
		(*size)++;
	}

	for (i = i + 1; i < COUNT(attestationTags); ++i) {
		/* KM_TAG_APPLICATION_ID and KM_TAG_ATTESTATION_APPLICATION_ID
		 * are encoded in key_description params, not in key_char.
		 * They should be encoded as an OCTET_STRING.
		 */
		if (attestationTags[i] == (KM_TAG_APPLICATION_ID & 0x0FFFFFFF) ||
		    attestationTags[i] == (KM_TAG_ATTESTATION_APPLICATION_ID & 0x0FFFFFFF)) {
			if (hw_flag)
				continue;

			for (j = 0; j < params->length; ++j) {
				if (attestationTags[i] !=
					(params->params[j].tag & 0x0FFFFFFF))
					continue;

				encodeTagOctetString(&chars_tags[*size],
						     &chars_list[*size],
						     attestationTags[i],
						     params->params[j].key_param.blob.data,
						     params->params[j].key_param.blob.data_length);
				(*size)++;
			}
			continue;
		}
		/* RootOfTrust encoding. This tag isn't contained in key_chr */
		if (attestationTags[i] == (KM_TAG_ROOT_OF_TRUST & 0x0FFFFFFF)) {
			if (!hw_flag)
				continue;

			switch (verified_boot_state) {
			case 0:
			case 1:
				LTC_SET_ASN1(attest->root_of_trust, 0,
					     LTC_ASN1_OCTET_STRING,
					     verifiedBootKey,
					     SHA256_BUFFER_SIZE);
				LTC_SET_ASN1(attest->root_of_trust, 1,
					     LTC_ASN1_BOOLEAN, &bool_T, 0);
				if (verified_boot_state)
					LTC_SET_ASN1(attest->root_of_trust, 2,
						     LTC_ASN1_ENUMERATED,
						     &secLvl_TE, 1);
				else
					LTC_SET_ASN1(attest->root_of_trust, 2,
						     LTC_ASN1_ENUMERATED,
						     &secLvl_SW, 1);
				break;
			case 2:
				LTC_SET_ASN1(attest->root_of_trust, 0,
					     LTC_ASN1_OCTET_STRING,
					     verifiedBootKey, 0);
				LTC_SET_ASN1(attest->root_of_trust, 1,
					     LTC_ASN1_BOOLEAN, &bool_F, 0);
				LTC_SET_ASN1(attest->root_of_trust, 2,
						     LTC_ASN1_ENUMERATED,
						     &version, 1);
				break;
			default:
				continue;
			}
			encodeTagSeq(&chars_tags[*size], &chars_list[*size],
				     attestationTags[i], attest->root_of_trust,
				     ROOTOFTRUST_SIZE);
			(*size)++;
			continue;
		}

		/* Setting other key characteristics */
		for (j = 0; j < key_chr->length; ++j) {
			if (attestationTags[i] !=
				(key_chr->params[j].tag & 0x0FFFFFFF))
				continue;

			switch (key_chr->params[j].tag) {
			case KM_TAG_ACTIVE_DATETIME:
			case KM_TAG_CREATION_DATETIME:
			case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
			case KM_TAG_USAGE_EXPIRE_DATETIME:
				_int =
					&key_chr->params[j].key_param.long_integer;
				encodeTagLong(&chars_tags[*size],
					     &chars_list[*size],
					     attestationTags[i],
					     _int);
				(*size)++;
				break;
			case KM_TAG_EC_CURVE:
			case KM_TAG_RSA_PUBLIC_EXPONENT:
			case KM_TAG_USER_AUTH_TYPE:
			case KM_TAG_AUTH_TIMEOUT:
			case KM_TAG_ORIGIN:
			case KM_TAG_OS_VERSION:
			case KM_TAG_OS_PATCHLEVEL:
				_int =
					&key_chr->params[j].key_param.long_integer;
				encodeTagInt(&chars_tags[*size],
					     &chars_list[*size],
					     attestationTags[i],
					     _int);
				(*size)++;
				break;
			case KM_TAG_NO_AUTH_REQUIRED:
			case KM_TAG_ALLOW_WHILE_ON_BODY:
			case KM_TAG_ALL_APPLICATIONS:
			case KM_TAG_ROLLBACK_RESISTANT:
				encodeTagNul(&chars_tags[*size],
					     &chars_list[*size],
					     attestationTags[i]);
				(*size)++;
				break;
			default:
				break;
			}

		}
	}

	for (i = 0; i < (*size); ++i)
		LTC_SET_ASN1(final_list, i, LTC_ASN1_EXP_TAG, &chars_tags[i], 1);
}

int encodeKeyDescription(der_extValue *extVal,
			 unsigned char **keyDescription,
			 keymaster_key_param_set_t *key_descr,
			 keymaster_key_characteristics_t *key_chars,
			 uint8_t vb_state)
{
	der_attestExtension *attestExt;
	int res = 0;
	size_t i;
	ULONG size = 0;

	sw_prps_size = 0;
	sw_dgst_size = 0;
	sw_pdng_size = 0;

	hw_prps_size = 0;
	hw_dgst_size = 0;
	hw_pdng_size = 0;

	attestExt = malloc(sizeof(*attestExt));

	if (!attestExt)
		return 1;

	LTC_SET_ASN1(attestExt->arr, 0, LTC_ASN1_SHORT_INTEGER, &version, 1);
	LTC_SET_ASN1(attestExt->arr, 1, LTC_ASN1_ENUMERATED, &secLvl_TE, 1);
	LTC_SET_ASN1(attestExt->arr, 2, LTC_ASN1_SHORT_INTEGER, &km_version, 1);
	LTC_SET_ASN1(attestExt->arr, 3, LTC_ASN1_ENUMERATED, &secLvl_TE, 1);

	for (i = 0; i < key_descr->length; ++i) {
		if ((key_descr->params + i)->tag ==
			KM_TAG_ATTESTATION_CHALLENGE) {
			LTC_SET_ASN1(attestExt->arr, 4, LTC_ASN1_OCTET_STRING,
				     key_descr->params[i].key_param.blob.data,
				     key_descr->params[i].key_param.blob.data_length);
			break;
		}
	}

	if (i == key_descr->length) /* set dummy zero-length string */
		LTC_SET_ASN1(attestExt->arr, 4, LTC_ASN1_OCTET_STRING,
			     rootName, 0);

	for (i = 0; i < key_descr->length; ++i) {
		if ((key_descr->params + i)->tag == KM_TAG_UNIQUE_ID) {
			LTC_SET_ASN1(attestExt->arr, 5, LTC_ASN1_OCTET_STRING,
				     key_descr->params[i].key_param.blob.data,
				     key_descr->params[i].key_param.blob.data_length);
			break;
		}
	}

	if (i == key_descr->length) /* set dummy zero-length string */
		LTC_SET_ASN1(attestExt->arr, 5, LTC_ASN1_OCTET_STRING,
			     rootName, 0);

	fill_key_chars(&(key_chars->sw_enforced), &(key_chars->hw_enforced),
		       &extVal[0]);
	/* sw_enforced */
	set_chars(attestExt, 0, &(key_chars->sw_enforced), key_descr, vb_state);
	/* hw_enforced */
	set_chars(attestExt, 1, &(key_chars->hw_enforced), key_descr, vb_state);

	LTC_SET_ASN1(attestExt->arr, 6, X509_AUTH_LIST, attestExt->sw,
		     attestExt->sw_size);
	LTC_SET_ASN1(attestExt->arr, 7, X509_AUTH_LIST, attestExt->hw,
		     attestExt->hw_size);

	res = der_length_sequence(attestExt->arr, KEY_DESCRPTN_SIZE, &size);
	if (res != CRYPT_OK)
		goto exit;

	*keyDescription = malloc(size);

	if (!(*keyDescription))
		goto exit;

	extVal[1].val_size = size;
	res = der_encode_sequence(attestExt->arr, KEY_DESCRPTN_SIZE,
				  *keyDescription, &size);

	if (res != CRYPT_OK || extVal[1].val_size != size) {
		res = 1;
		goto exit;
	}

	extVal[1].value = *keyDescription;

exit:
	free(attestExt);
	return res;
}

int encode_ecc_sign_256(uint8_t *sign, ULONG *sign_size)
{
	uint32_t res = CRYPT_OK;
	ULONG key_size = *sign_size / 2;
	void *r;
	void *s;

	res = createBigNum(&r, (void *)sign, key_size);
	if (res != CRYPT_OK)
		goto exit;
	res = createBigNum(&s, (void *)(sign + key_size), key_size);
	if (res != CRYPT_OK)
		goto exit;

	*sign_size = EC_SIGN_BUFFER_SIZE;
	res = der_encode_sequence_multi(sign, sign_size,
				LTC_ASN1_INTEGER, 1UL, r,
				LTC_ASN1_INTEGER, 1UL, s,
				LTC_ASN1_EOL, 0UL, NULL);
	if (res != CRYPT_OK)
		EMSG("Failed to encode EC sign res = %x", res);

exit:
	ltc_mp.deinit(r);
	ltc_mp.deinit(s);

	return res;
}
