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

/* File contains functions, which provide X.509 support for attestation. */
#include "x509_attestation.h"

const unsigned long unitName_oid[] = { 2, 5, 4, 11 };
const unsigned long organizationName_oid[] = { 2, 5, 4, 10 };
const unsigned long commonName_oid[] = { 2, 5, 4, 3 };

const unsigned long rsaEncryption[]    = { 1, 2, 840, 113549, 1, 1, 1 };
const unsigned long sha1RSAEnc_oid[]   = { 1, 2, 840, 113549, 1, 1, 5 };
const unsigned long sha224RSAEnc_oid[] = { 1, 2, 840, 113549, 1, 1, 14 };
const unsigned long sha256RSAEnc_oid[] = { 1, 2, 840, 113549, 1, 1, 11 };
const unsigned long sha384RSAEnc_oid[] = { 1, 2, 840, 113549, 1, 1, 12 };
const unsigned long sha512RSAEnc_oid[] = { 1, 2, 840, 113549, 1, 1, 13 };

const unsigned long id_ecPublicKey[]   = { 1, 2, 840, 10045, 2, 1 };
const unsigned long ecdsaSHA224_oid[]  = { 1, 2, 840, 10045, 4, 3, 1 };
const unsigned long ecdsaSHA256_oid[]  = { 1, 2, 840, 10045, 4, 3, 2 };
const unsigned long ecdsaSHA384_oid[]  = { 1, 2, 840, 10045, 4, 3, 3 };
const unsigned long ecdsaSHA512_oid[]  = { 1, 2, 840, 10045, 4, 3, 4 };
const unsigned long secp192r1_oid[]    = { 1, 2, 840, 10045, 3, 1, 1 };
const unsigned long secp224r1_oid[]    = { 1, 3, 132, 0, 33 };
const unsigned long secp256r1_oid[]    = { 1, 2, 840, 10045, 3, 1, 7 };
const unsigned long secp384r1_oid[]    = { 1, 3, 132, 0, 34 };
const unsigned long secp521r1_oid[]    = { 1, 3, 132, 0, 35 };

const unsigned long subjKeyId_oid[]	 = { 2, 5, 29, 14 };
const unsigned long keyUsage_oid[]	 = { 2, 5, 29, 15 };
const unsigned long basicConst_oid[]	 = { 2, 5, 29, 19 };
const unsigned long crlDistPoint_oid[]	 = { 2, 5, 29, 31 };
const unsigned long authorityKeyId_oid[] = { 2, 5, 29, 35 };
const unsigned long attestation_oid[]    = { 1, 3, 6, 1, 4, 1, 11129, 2, 1, 17 };

const char *rootUnitNameRSA = "Attestation RSA root CA";
const char *rootUnitNameECC = "Attestation ECC root CA";
const char *rootName = "Android";
const char *attestationName = "Android Keystore Key";

ULONG version = 2;	/* x509 version of cert. v3 used. */
const ULONG versionTag;	/* tag value for version field. */
const ULONG serialNumber = 1;	/* serialNumber of cert. */
const ULONG km_version = 3; /* keymaster version */

const int bool_T = 1;
const int bool_F;

const ULONG secLvl_SW;
const ULONG secLvl_TE = 1;

/* ========== Predefined OIDs ========== */

static const OidStruct rsaOidSt = { rsaEncryption, COUNT(rsaEncryption) };
static const OidStruct ecOidSt192[] = { {id_ecPublicKey, COUNT(id_ecPublicKey)},
					{secp192r1_oid, COUNT(secp192r1_oid)} };
static const OidStruct ecOidSt224[] = { {id_ecPublicKey, COUNT(id_ecPublicKey)},
					{secp224r1_oid, COUNT(secp224r1_oid)} };
static const OidStruct ecOidSt256[] = { {id_ecPublicKey, COUNT(id_ecPublicKey)},
				      {secp256r1_oid, COUNT(secp256r1_oid)} };
static const OidStruct ecOidSt384[] = { {id_ecPublicKey, COUNT(id_ecPublicKey)},
				      {secp384r1_oid, COUNT(secp384r1_oid)} };
static const OidStruct ecOidSt521[] = { {id_ecPublicKey, COUNT(id_ecPublicKey)},
				      {secp521r1_oid, COUNT(secp521r1_oid)} };
static const OidStruct rootOidRSA = { sha256RSAEnc_oid, COUNT(sha256RSAEnc_oid) };
static const OidStruct rootOidECC = { ecdsaSHA256_oid, COUNT(ecdsaSHA256_oid) };

/* root extensions oids */
static const OidStruct keyUsageOidSt = { keyUsage_oid, COUNT(keyUsage_oid) };
static const OidStruct basicConstOidSt = { basicConst_oid, COUNT(basicConst_oid) };
static const OidStruct subjKeyIdOidSt = { subjKeyId_oid, COUNT(subjKeyId_oid) };

/* root extensions values */
static const unsigned char rootKeyUsageVal[]   = {0x03, 0x02, 0x01, 0x06};
static const unsigned char rootBasicConstVal[] = {0x30, 0x03, 0x01, 0x01, 0xFF};

/* attestation oids */
static const OidStruct crlDistPOidSt = { crlDistPoint_oid, COUNT(crlDistPoint_oid) };
static const OidStruct attestOidSt = { attestation_oid, COUNT(attestation_oid) };

static const unsigned char attestCrlDistPVal[]  = {0x30, 0x02, 0x05, 0x00};

/* DER encoded root RSA name. */
static int setRootNameRSA(der_oidName *derNames, int size)
{
	SampleName name[NAME_SEQ_SIZE];

	if (size != NAME_SEQ_SIZE)
		return 1;

	/* set root unit name */
	name[0].oidSt.oid = unitName_oid;
	name[0].oidSt.oid_size = COUNT(unitName_oid);
	name[0].name = rootUnitNameRSA;

	/* set root organization name */
	name[1].oidSt.oid = organizationName_oid;
	name[1].oidSt.oid_size = COUNT(organizationName_oid);
	name[1].name = rootName;

	/* set root common name */
	name[2].oidSt.oid = commonName_oid;
	name[2].oidSt.oid_size = COUNT(commonName_oid);
	name[2].name = rootName;

	encodeSampleNames(derNames, name, NAME_SEQ_SIZE);

	return 0;
}

/* DER encoded root ECC name. */
static int setRootNameECC(der_oidName *derNames, int size)
{
	SampleName name[NAME_SEQ_SIZE];

	if (size != NAME_SEQ_SIZE)
		return 1;

	/* set root unit name */
	name[0].oidSt.oid = unitName_oid;
	name[0].oidSt.oid_size = COUNT(unitName_oid);
	name[0].name = rootUnitNameECC;

	/* set root organization name */
	name[1].oidSt.oid = organizationName_oid;
	name[1].oidSt.oid_size = COUNT(organizationName_oid);
	name[1].name = rootName;

	/* set root common name */
	name[2].oidSt.oid = commonName_oid;
	name[2].oidSt.oid_size = COUNT(commonName_oid);
	name[2].name = rootName;

	encodeSampleNames(derNames, name, NAME_SEQ_SIZE);

	return 0;
}

/* DER encoded attestation name. */
static int setAttestationName(der_oidName *derNames, int size)
{
	SampleName name[ATTESTATION_NAME_SIZE];

	if (size != ATTESTATION_NAME_SIZE)
		return 1;

	/* set root unit name */
	name[0].oidSt.oid = commonName_oid;
	name[0].oidSt.oid_size = COUNT(commonName_oid);
	name[0].name = attestationName;

	encodeSampleNames(derNames, name, ATTESTATION_NAME_SIZE);

	return 0;
}

/* DER encoded root algId (signature). */
void rootAlgIdEncode(der_algId *algId, const int rsa)
{
	if (rsa)
		encodeAlgOidRSA(algId, &rootOidRSA);
	else
		encodeAlgOidECC(algId, &rootOidECC);
}

/* DER encoded Rsa AlgId for SubjectPublicKeyInfo */
void rsaAlgIdEncode(der_algId *algId)
{
	encodeAlgOidRSA(algId, &rsaOidSt);
}

/* DER encoded ECC AlgId for SubjectPublicKeyInfo */
void eccAlgIdEncode(der_algId *algId, uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		encodeAlgOidECC_SPK(algId, ecOidSt192);
		return;
	case TEE_ECC_CURVE_NIST_P224:
		encodeAlgOidECC_SPK(algId, ecOidSt224);
		return;
	case TEE_ECC_CURVE_NIST_P256:
		encodeAlgOidECC_SPK(algId, ecOidSt256);
		return;
	case TEE_ECC_CURVE_NIST_P384:
		encodeAlgOidECC_SPK(algId, ecOidSt384);
		return;
	case TEE_ECC_CURVE_NIST_P521:
		encodeAlgOidECC_SPK(algId, ecOidSt521);
		return;
	default:
		return;
	}
}

/* Encode name for root cert. */
void rootNameEncode(ltc_asn1_list *name, der_oidName *derNames, ULONG size,
					int rsa)
{
	if (rsa)
		encodeRDNName(name, derNames, size, setRootNameRSA);
	else
		encodeRDNName(name, derNames, size, setRootNameECC);
}

/* Encode name for attestation cert. */
void attestNameEncode(ltc_asn1_list *name, der_oidName *derNames, ULONG size)
{
	encodeRDNName(name, derNames, size, setAttestationName);
}

/* Encode version for any cert. */
void versionEncode(ltc_exp_tag *tag, ltc_asn1_list *asnInt)
{
	encodeTagInt(tag, asnInt, versionTag, &version);
}

/* DER encoded root extensions. */
static int setRootExtensions(der_Extension *der_extensions,
			     der_extValue *values,
			     int size)
{
	OneExtension extensions[ROOT_EXT_SIZE];

	if (size != ROOT_EXT_SIZE)
		return 1;

	/* set root keyUsage. Critical = true */
	extensions[0].extOid = keyUsageOidSt;
	extensions[0].critical = &bool_T;
	extensions[0].extValue = (unsigned char *)rootKeyUsageVal;
	extensions[0].val_size = COUNT(rootKeyUsageVal);

	/* set root basicConstraints. Critical = true */
	extensions[1].extOid = basicConstOidSt;
	extensions[1].critical = &bool_T;
	extensions[1].extValue = (unsigned char *)rootBasicConstVal;
	extensions[1].val_size = COUNT(rootBasicConstVal);

	/* set root subjectKeyIdentifier. Critical = false */
	extensions[2].extOid = subjKeyIdOidSt;
	extensions[2].critical = &bool_F;
	extensions[2].extValue = values->value;
	extensions[2].val_size = values->val_size;

	encodeOneExtension(der_extensions, extensions, ROOT_EXT_SIZE);

	return 0;
}

/* DER encoded attestation extensions. */
static int setAttestationExtensions(der_Extension *der_extensions,
				    der_extValue *values, int size)
{
	OneExtension extensions[ATTEST_EXT_SIZE];

	if (size != ATTEST_EXT_SIZE)
		return 1;

	/* set attestation keyUsage. Critical = true */
	extensions[0].extOid = keyUsageOidSt;
	extensions[0].critical = &bool_T;
	extensions[0].extValue = values[0].value;
	extensions[0].val_size = values[0].val_size;

	/* set attestation cRLDistrPoints (TBD). Critical = false */
	extensions[1].extOid = crlDistPOidSt;
	extensions[1].critical = &bool_F;
	extensions[1].extValue = (unsigned char *)attestCrlDistPVal;
	extensions[1].val_size = COUNT(attestCrlDistPVal);

	/* set attestation extension. Critical = false */
	extensions[2].extOid = attestOidSt;
	extensions[2].critical = &bool_F;
	extensions[2].extValue = values[1].value;
	extensions[2].val_size = values[1].val_size;

	encodeOneExtension(der_extensions, extensions, ATTEST_EXT_SIZE);

	return 0;
}

/* Encode extensions for root cert. */
void rootExtEncode(ltc_asn1_list *extensions, der_Extension *der_extensions,
		   der_extValue *values, ULONG size)
{
	encodeExtensions(extensions, der_extensions, values, size,
			 setRootExtensions);
}

/* Encode extensions for attestation cert. */
void attestExtEncode(ltc_asn1_list *extensions, der_Extension *der_extensions,
		     der_extValue *values, ULONG size)
{
	encodeExtensions(extensions, der_extensions, values, size,
			 setAttestationExtensions);
}

int rootTBSencodeRSA_BN(der_TBS *tbs, der_algId *alg, void *mod, void *exp,
			unsigned char *out, ULONG *outlen,
			unsigned char **pk, ULONG *pk_size)
{
	int res;

	versionEncode(&tbs->ver_tag, &tbs->der_ver);
	LTC_SET_ASN1(tbs->tbs, 0, LTC_ASN1_EXP_TAG, &tbs->ver_tag, 1);

	LTC_SET_ASN1(tbs->tbs, 1, LTC_ASN1_SHORT_INTEGER, &serialNumber, 1);

	rootAlgIdEncode(alg, 1);
	LTC_SET_ASN1(tbs->tbs, 2, X509_ALGID, alg, ALG_ID_SIZE);

	rootNameEncode(tbs->root_name, tbs->root_derNames, NAME_SEQ_SIZE, 1);
	LTC_SET_ASN1(tbs->tbs, 3, LTC_ASN1_SEQUENCE, tbs->root_name,
		     NAME_SEQ_SIZE);

	encodeHardcodedValidity(&tbs->validity);
	LTC_SET_ASN1(tbs->tbs, 4, X509_VALIDITY, tbs->validity.arr, VAL_SIZE);

	LTC_SET_ASN1(tbs->tbs, 5, LTC_ASN1_SEQUENCE, tbs->root_name,
		     NAME_SEQ_SIZE);

	res = encodeSubPubKeyInfoRSA_BN(&tbs->keyInfo.rsa, mod, exp, pk,
					pk_size);
	if (res != CRYPT_OK)
		return -1;

	LTC_SET_ASN1(tbs->tbs, 6, X509_PK_INFO, tbs->keyInfo.rsa.seqArr,
		     SUBJ_PK_INFO_SIZE);

	res = encodeSubjKeyId(&tbs->rootSubjKeyId, *pk, *pk_size);
	if (res != CRYPT_OK)
		return -1;

	rootExtEncode(tbs->all_extensions, tbs->der_extension,
		      &tbs->rootSubjKeyId, ROOT_EXT_SIZE);
	encodeTagSeq(&tbs->ext_tag, &tbs->extensions, 3, tbs->all_extensions,
		     ROOT_EXT_SIZE);
	LTC_SET_ASN1(tbs->tbs, 7, LTC_ASN1_EXP_TAG, &tbs->ext_tag, 1);

	//Signature computed on ASN.1 DER-encoded tbsCertificate.
	return der_encode_sequence(tbs->tbs, TBS_SIZE, out, outlen);
}

int rootTBSencodeECC_BN(der_TBS *tbs, der_algId *alg, void *x, void *y,
			unsigned char *out, ULONG *outlen,
			unsigned char **pk, ULONG *pk_size)
{
	int res;

	versionEncode(&tbs->ver_tag, &tbs->der_ver);
	LTC_SET_ASN1(tbs->tbs, 0, LTC_ASN1_EXP_TAG, &tbs->ver_tag, 1);

	LTC_SET_ASN1(tbs->tbs, 1, LTC_ASN1_SHORT_INTEGER, &serialNumber, 1);

	rootAlgIdEncode(alg, 0);
	LTC_SET_ASN1(tbs->tbs, 2, X509_ALGID, alg, ALG_ID_SIZE);

	rootNameEncode(tbs->root_name, tbs->root_derNames, NAME_SEQ_SIZE, 0);
	LTC_SET_ASN1(tbs->tbs, 3, LTC_ASN1_SEQUENCE, tbs->root_name,
		     NAME_SEQ_SIZE);

	encodeHardcodedValidity(&tbs->validity);
	LTC_SET_ASN1(tbs->tbs, 4, X509_VALIDITY, tbs->validity.arr, VAL_SIZE);

	LTC_SET_ASN1(tbs->tbs, 5, LTC_ASN1_SEQUENCE, tbs->root_name,
		     NAME_SEQ_SIZE);

	res = encodeSubPubKeyInfoECC_BN(&tbs->keyInfo.ecc,
					TEE_ECC_CURVE_NIST_P256, x, y, pk,
					pk_size);
	if (res != CRYPT_OK)
		return -1;

	LTC_SET_ASN1(tbs->tbs, 6, X509_PK_INFO, tbs->keyInfo.ecc.seqArr,
		     SUBJ_PK_INFO_SIZE);

	res = encodeSubjKeyId(&tbs->rootSubjKeyId, *pk, *pk_size);
	if (res != CRYPT_OK)
		return -1;

	rootExtEncode(tbs->all_extensions, tbs->der_extension,
		      &tbs->rootSubjKeyId, ROOT_EXT_SIZE);
	encodeTagSeq(&tbs->ext_tag, &tbs->extensions, 3, tbs->all_extensions,
		     ROOT_EXT_SIZE);
	LTC_SET_ASN1(tbs->tbs, 7, LTC_ASN1_EXP_TAG, &tbs->ext_tag, 1);

	//Signature computed on ASN.1 DER-encoded tbsCertificate.
	return der_encode_sequence(tbs->tbs, TBS_SIZE, out, outlen);
}

int attestTBSencodeRSA(der_TBS_ATTEST *tbs, der_algId *alg,
		       const uint8_t *attest_key_attr,
		       unsigned char *out, ULONG *outlen,
		       unsigned char **pk, ULONG *pk_size)
{
	int res;
	const unsigned char *mod;
	const unsigned char *exp;
	ULONG m_size = 0;
	ULONG e_size = 0;

	/* Attested RSA key extraction from blob */
	memcpy(&m_size, &attest_key_attr[0], sizeof(uint32_t));
	if (m_size > RSA_MAX_KEY_BUFFER_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Wrong memory buffer length");
		return res;
	}
	mod = &attest_key_attr[sizeof(uint32_t)];

	memcpy(&e_size, &attest_key_attr[sizeof(uint32_t) + m_size],
	       sizeof(uint32_t));
	if (e_size > RSA_MAX_KEY_BUFFER_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Wrong memory buffer length");
		return res;
	}
	exp = &attest_key_attr[sizeof(uint32_t) * 2 + m_size];

	/* TBS filling */
	versionEncode(&tbs->ver_tag, &tbs->der_ver);
	LTC_SET_ASN1(tbs->tbs, 0, LTC_ASN1_EXP_TAG, &tbs->ver_tag, 1);

	LTC_SET_ASN1(tbs->tbs, 1, LTC_ASN1_SHORT_INTEGER, &serialNumber, 1);
	/* same alg as for root cert */
	rootAlgIdEncode(alg, 1);
	LTC_SET_ASN1(tbs->tbs, 2, X509_ALGID, alg, ALG_ID_SIZE);

	rootNameEncode(tbs->issuer, tbs->issuer_der, NAME_SEQ_SIZE, 1);
	LTC_SET_ASN1(tbs->tbs, 3, LTC_ASN1_SEQUENCE, tbs->issuer, NAME_SEQ_SIZE);

	encodeHardcodedValidity(&tbs->validity);
	LTC_SET_ASN1(tbs->tbs, 4, X509_VALIDITY, tbs->validity.arr, VAL_SIZE);

	attestNameEncode(tbs->subject, tbs->subject_der, ATTESTATION_NAME_SIZE);
	LTC_SET_ASN1(tbs->tbs, 5, LTC_ASN1_SEQUENCE, tbs->subject,
			     ATTESTATION_NAME_SIZE);

	res = encodeSubPubKeyInfoRSA(&tbs->keyInfo.rsa, mod, m_size,
				     exp, e_size, pk, pk_size);
	if (res != CRYPT_OK)
		return -1;

	LTC_SET_ASN1(tbs->tbs, 6, X509_PK_INFO, tbs->keyInfo.rsa.seqArr,
		     SUBJ_PK_INFO_SIZE);

	attestExtEncode(tbs->all_extensions, tbs->der_extension, tbs->extVals,
			ATTEST_EXT_SIZE);
	encodeTagSeq(&tbs->ext_tag, &tbs->extensions, 3, tbs->all_extensions,
		     ATTEST_EXT_SIZE);
	LTC_SET_ASN1(tbs->tbs, 7, LTC_ASN1_EXP_TAG, &tbs->ext_tag, 1);

	/* Signature computed on ASN.1 DER-encoded tbsCertificate. */
	return der_encode_sequence(tbs->tbs, TBS_SIZE, out, outlen);
}

int attestTBSencodeECC(der_TBS_ATTEST *tbs, der_algId *alg,
		       const uint8_t *attest_key_attr,
		       unsigned char *out, ULONG *outlen,
		       unsigned char **pk, ULONG *pk_size)
{
	int res;
	const unsigned char *x;
	const unsigned char *y;
	ULONG x_size = 0;
	ULONG y_size = 0;

	uint32_t curve = 0;
	uint32_t curve_size = 0;

	/* Attested EC key extraction from blob */
	memcpy(&curve_size, &attest_key_attr[0], sizeof(uint32_t));
	if (curve_size > sizeof(uint32_t)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Wrong memory buffer length");
		return res;
	}
	memcpy(&curve, &attest_key_attr[sizeof(uint32_t)],
	       sizeof(uint32_t));

	memcpy(&x_size, &attest_key_attr[sizeof(uint32_t) * 2],
	       sizeof(uint32_t));
	if (x_size > EC_MAX_KEY_BUFFER_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Wrong memory buffer length");
		return res;
	}
	x = &attest_key_attr[sizeof(uint32_t) * 3];

	memcpy(&y_size, &attest_key_attr[sizeof(uint32_t) * 3 + x_size],
	       sizeof(uint32_t));
	if (y_size > EC_MAX_KEY_BUFFER_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		EMSG("Wrong memory buffer length");
		return res;
	}
	y = &attest_key_attr[sizeof(uint32_t) * 4 + x_size];

	/* TBS filling */
	versionEncode(&tbs->ver_tag, &tbs->der_ver);
	LTC_SET_ASN1(tbs->tbs, 0, LTC_ASN1_EXP_TAG, &tbs->ver_tag, 1);

	LTC_SET_ASN1(tbs->tbs, 1, LTC_ASN1_SHORT_INTEGER, &serialNumber, 1);
	/* sama alg as for root cert */
	rootAlgIdEncode(alg, 0);
	LTC_SET_ASN1(tbs->tbs, 2, X509_ALGID, alg, ALG_ID_SIZE);

	rootNameEncode(tbs->issuer, tbs->issuer_der, NAME_SEQ_SIZE, 0);
	LTC_SET_ASN1(tbs->tbs, 3, LTC_ASN1_SEQUENCE, tbs->issuer, NAME_SEQ_SIZE);

	encodeHardcodedValidity(&tbs->validity);
	LTC_SET_ASN1(tbs->tbs, 4, X509_VALIDITY, tbs->validity.arr, VAL_SIZE);

	attestNameEncode(tbs->subject, tbs->subject_der, ATTESTATION_NAME_SIZE);
	LTC_SET_ASN1(tbs->tbs, 5, LTC_ASN1_SEQUENCE, tbs->subject,
		     ATTESTATION_NAME_SIZE);

	res = encodeSubPubKeyInfoECC(&tbs->keyInfo.ecc, curve, x, x_size,
				     y, y_size, pk, pk_size);
	if (res != CRYPT_OK)
		return -1;

	LTC_SET_ASN1(tbs->tbs, 6, X509_PK_INFO, tbs->keyInfo.ecc.seqArr,
		     SUBJ_PK_INFO_SIZE);

	attestExtEncode(tbs->all_extensions, tbs->der_extension, tbs->extVals,
			ATTEST_EXT_SIZE);
	encodeTagSeq(&tbs->ext_tag, &tbs->extensions, 3, tbs->all_extensions,
		     ATTEST_EXT_SIZE);
	LTC_SET_ASN1(tbs->tbs, 7, LTC_ASN1_EXP_TAG, &tbs->ext_tag, 1);

	/* Signature computed on ASN.1 DER-encoded tbsCertificate. */
	return der_encode_sequence(tbs->tbs, TBS_SIZE, out, outlen);
}
