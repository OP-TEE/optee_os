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

#ifndef X509_ATTESTATION_H_
#define X509_ATTESTATION_H_

#include <stdlib.h>
#include <stdint.h>

#include <tee_api_defines.h>
#include <tomcrypt.h>
#include "x509_constants.h"
#include "keymaster_defs.h"

/* Max key sizes */
#define RSA_MAX_KEY_SIZE 4096U
#define EC_MAX_KEY_SIZE 521U
/* Max sign sizes */
#define EC_SIGN_BUFFER_SIZE 72U
#define RSA_SIGN_BUFFER_SIZE 128U

#define SHA256_BUFFER_SIZE 32U

/* List of Supported ECC Curves (from GP API) */
#define TEE_ECC_CURVE_NIST_P192             0x00000001
#define TEE_ECC_CURVE_NIST_P224             0x00000002
#define TEE_ECC_CURVE_NIST_P256             0x00000003
#define TEE_ECC_CURVE_NIST_P384             0x00000004
#define TEE_ECC_CURVE_NIST_P521             0x00000005

#define RSA_MAX_KEY_BUFFER_SIZE (RSA_MAX_KEY_SIZE / 8)
#define EC_MAX_KEY_BUFFER_SIZE (EC_MAX_KEY_SIZE / 8 + 1)

/* Alias for types */
#define X509_TBS	LTC_ASN1_SEQUENCE
#define X509_ALGID	LTC_ASN1_SEQUENCE
#define X509_VALIDITY	LTC_ASN1_SEQUENCE
#define X509_PK_INFO	LTC_ASN1_SEQUENCE
#define X509_EXTENSIONS	LTC_ASN1_SEQUENCE
#define X509_AUTH_LIST	LTC_ASN1_SEQUENCE
#define X509_SIGN_VAL	LTC_ASN1_RAW_BIT_STRING

#define COUNT(p) (sizeof(p) / sizeof(*p))
#define ULONG unsigned long

#define CERT_SIZE 3
#define TBS_SIZE  8

/* Validity size (notBefore, notAfter) */
#define VAL_SIZE  2

typedef struct {
	const ULONG *oid;
	ULONG oid_size;
} OidStruct;

typedef struct {
	OidStruct oidSt;
	const char *name;
} SampleName;

/* size of sequence, which hold oid and printable string */
#define NAME_SIZE 2

/* Holds ASN.1 oid and printable string */
typedef struct _der_oidName {
	ltc_asn1_list sequence;
	ltc_asn1_list arrName[NAME_SIZE];
} der_oidName;

/* max number of elements in RDN field */
#define NAME_SEQ_SIZE 3

/* max number of elements in RDN field */
#define ATTESTATION_NAME_SIZE 1

/* max size of AlgorithmIdentifier (which hold oid and NULL for RSA and just
 * oid for ecdsa)
 */
#define ALG_ID_SIZE 2

/* Holds ASN.1 AlgorithmIdentifier */
typedef ltc_asn1_list der_algId[ALG_ID_SIZE];

typedef struct {
	ltc_asn1_list sequence;
	ltc_asn1_list arr[VAL_SIZE];
	ltc_utctime notBefore;
	ltc_utctime notAfter;
} der_Validity;

#define SUBJ_PK_INFO_SIZE 2
#define RSA_PUB_KEY_SIZE 2

/* Holds RSA SubjectPublicKeyInfo */
typedef struct {
	der_algId algId;
	ltc_asn1_list arr[RSA_PUB_KEY_SIZE];
	ltc_asn1_list seqArr[SUBJ_PK_INFO_SIZE];
} der_rsaKeyInfo;

/* Holds ECC SubjectPublicKeyInfo */
typedef struct {
	der_algId algId;
	ltc_asn1_list seqArr[SUBJ_PK_INFO_SIZE];
} der_eccKeyInfo;

typedef union {
	der_rsaKeyInfo rsa;
	der_eccKeyInfo ecc;
} KeyInfo;

#define SINGLE_EXT_SIZE  3
#define MAX_EXT_VAL 30
#define ROOT_EXT_SIZE 3
#define ATTEST_EXT_SIZE 3
#define ATTEST_EXT_VALS 2

/* Holds single value of extension. */
typedef struct {
	unsigned char *value;
	ULONG val_size;
} der_extValue;

/* Array for SubjectKeyIdentifier extension (sha1 from public key, only root) */
#define SUBJ_KEY_ID_SIZE 22
extern unsigned char SubjKeyId[SUBJ_KEY_ID_SIZE];

/* Hardcoded SHA256 hash of the verified boot key from avb_verify.c */
extern const unsigned char verifiedBootKey[SHA256_BUFFER_SIZE];

typedef struct {
	OidStruct extOid;
	const int *critical;
	unsigned char *extValue;
	ULONG val_size;
} OneExtension;

/* Array which contains one der-encoded extension (SEQUENCE of 3 types). */
typedef ltc_asn1_list der_Extension[SINGLE_EXT_SIZE];

typedef struct {
	ltc_exp_tag    ver_tag;
	ltc_asn1_list  der_ver;
	ltc_asn1_list  root_name[NAME_SEQ_SIZE];
	der_oidName    root_derNames[NAME_SEQ_SIZE];
	der_Validity   validity;
	KeyInfo keyInfo;
	ltc_exp_tag    ext_tag;
	ltc_asn1_list  extensions;
	ltc_asn1_list  all_extensions[ROOT_EXT_SIZE];
	der_Extension  der_extension[ROOT_EXT_SIZE];
	der_extValue   rootSubjKeyId;
	ltc_asn1_list  tbs[TBS_SIZE];
} der_TBS;

/* Size of attestation extension.
 * See https://source.android.com/security/keystore/attestation
 */
#define KEY_DESCRPTN_SIZE 8
/* Max size of AuthorizationList sequence */
#define AUTH_LIST_SIZE 31
/* Max sizes of some KM Tags */
#define KEY_PURPOSE_SIZE 6
#define KEY_DIGEST_SIZE 7
#define KEY_PADDING_SIZE 6
#define ROOTOFTRUST_SIZE 3


typedef struct {
	ltc_asn1_list arr[KEY_DESCRPTN_SIZE];
	ltc_exp_tag swEnforced[AUTH_LIST_SIZE];
	ltc_exp_tag hwEnforced[AUTH_LIST_SIZE];
	ltc_asn1_list swEnfList[AUTH_LIST_SIZE];
	ltc_asn1_list hwEnfList[AUTH_LIST_SIZE];
	ltc_asn1_list sw[AUTH_LIST_SIZE];
	ltc_asn1_list hw[AUTH_LIST_SIZE];
	ULONG sw_size;
	ULONG hw_size;
	ltc_asn1_list root_of_trust[ROOTOFTRUST_SIZE];
} der_attestExtension;

typedef struct {
	ltc_exp_tag    ver_tag;
	ltc_asn1_list  der_ver;
	ltc_asn1_list  issuer[NAME_SEQ_SIZE];
	der_oidName    issuer_der[NAME_SEQ_SIZE];
	der_Validity   validity;
	ltc_asn1_list  subject[ATTESTATION_NAME_SIZE];
	der_oidName    subject_der[ATTESTATION_NAME_SIZE];
	KeyInfo keyInfo;
	ltc_exp_tag    ext_tag;
	ltc_asn1_list  extensions;
	ltc_asn1_list  all_extensions[ATTEST_EXT_SIZE];
	der_Extension  der_extension[ATTEST_EXT_SIZE];
	der_extValue   extVals[ATTEST_EXT_VALS];
	ltc_asn1_list  tbs[TBS_SIZE];
} der_TBS_ATTEST;

typedef int (*NameSetter)(der_oidName *derNames, int size);

typedef int (*ExtSetter)(der_Extension *der_extensions, der_extValue *values,
						 int size);

/* Functions from encode.c */
void encodeAlgOidRSA(der_algId *algId, const OidStruct *oid);
void encodeAlgOidECC(der_algId *algId, const OidStruct *oid);
void encodeAlgOidECC_SPK(der_algId *algId, const OidStruct *oid);
void encodeSampleNames(der_oidName *cn, SampleName *sn, ULONG size);
int encodeRDNName(ltc_asn1_list *name, der_oidName *derNames, ULONG size,
				  NameSetter nameSetter);
void encodeTagInt(ltc_exp_tag *tag, ltc_asn1_list *asnInt, const ULONG tag_val,
		  ULONG *int_val);
void encodeTagLong(ltc_exp_tag *tag, ltc_asn1_list *asnInt, const ULONG tag_val,
		   ULONG *int_val);
void encodeTagSeq(ltc_exp_tag *tag, ltc_asn1_list *asnSeq, const ULONG tag_val,
		  void *sequence, const ULONG seq_size);
void encodeTagSetof(ltc_exp_tag *tag, ltc_asn1_list *asnSetof,
		    const ULONG tag_val, void *setof,
		    const ULONG setof_size);
void encodeTagNul(ltc_exp_tag *tag, ltc_asn1_list *asnNull, const ULONG tag_val);
void encodeTagOctetString(ltc_exp_tag *tag, ltc_asn1_list *asnOctStr,
			  const ULONG tag_val, void *string,
			  const ULONG str_size);


void encodeHardcodedValidity(der_Validity *validity);

int encodeSubPubKeyInfoRSA_BN(der_rsaKeyInfo *rsaKeyInfo,
			      const void *modulus, const void *exp,
			      unsigned char **pk, ULONG *pk_size);
int encodeSubPubKeyInfoECC_BN(der_eccKeyInfo *eccKeyInfo, uint32_t curve,
			      void *x, void *y,
			      unsigned char **pk, ULONG *pk_size);

int encodeSubPubKeyInfoRSA(der_rsaKeyInfo *rsaKeyInfo,
			   const unsigned char *modulus, const ULONG m_size,
			   const unsigned char *exp, const ULONG e_size,
			   unsigned char **pk, ULONG *pk_size);
int encodeSubPubKeyInfoECC(der_eccKeyInfo *eccKeyInfo, uint32_t curve,
			   const unsigned char *x, const ULONG x_size,
			   const unsigned char *y, const ULONG y_size,
			   unsigned char **pk, ULONG *pk_size);


int encodeSubjKeyId(der_extValue *extVal, const unsigned char *pk,
		    const ULONG pk_size);

void encodeOneExtension(der_Extension *derExt, OneExtension *ext, ULONG size);
int encodeExtensions(ltc_asn1_list *extensions, der_Extension *der_extensions,
		     der_extValue *values, ULONG size, ExtSetter extSetter);

int encodeKeyDescription(der_extValue *extVal, unsigned char **keyDescription,
			 keymaster_key_param_set_t *key_descr,
			 keymaster_key_characteristics_t *key_chars,
			 uint8_t vb_state);

int encode_ecc_sign_256(uint8_t *sign, ULONG *sign_size);

/* Functions from attestation.c */
void rootAlgIdEncode(der_algId *algId, const int rsa);
void rsaAlgIdEncode(der_algId *algId);
void eccAlgIdEncode(der_algId *algId, uint32_t curve);
void rootNameEncode(ltc_asn1_list *name, der_oidName *derNames, ULONG size,
		    int rsa);
void attestNameEncode(ltc_asn1_list *name, der_oidName *derNames, ULONG size);
void versionEncode(ltc_exp_tag *tag, ltc_asn1_list *asnInt);
void rootExtEncode(ltc_asn1_list *extensions, der_Extension *der_extensions,
		   der_extValue *values, ULONG size);
void attestExtEncode(ltc_asn1_list *extensions, der_Extension *der_extensions,
		     der_extValue *values, ULONG size);
int rootTBSencodeRSA_BN(der_TBS *tbs, der_algId *alg, void *mod, void *exp,
			unsigned char *out, ULONG *outlen,
			unsigned char **pk, ULONG *pk_size);
int rootTBSencodeECC_BN(der_TBS *tbs, der_algId *alg, void *x, void *y,
			unsigned char *out, ULONG *outlen,
			unsigned char **pk, ULONG *pk_size);
int attestTBSencodeRSA(der_TBS_ATTEST *tbs, der_algId *alg,
		       const uint8_t *attest_key_attr,
		       unsigned char *out, ULONG *outlen,
		       unsigned char **pk, ULONG *pk_size);
int attestTBSencodeECC(der_TBS_ATTEST *tbs, der_algId *alg,
		       const uint8_t *attest_key_attr,
		       unsigned char *out, ULONG *outlen,
		       unsigned char **pk, ULONG *pk_size);


#endif /* X509_ATTESTATION_H_ */
