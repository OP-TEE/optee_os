/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Definition of the cryptographic algorthim's OID in the
 *         ASN1 String format.
 *         Definition of the ASN1 DER tags.
 *
 * Computer Security Objects Register
 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 */
#ifndef __ASN1_OID_H__
#define __ASN1_OID_H__

#include <drvcrypt_hash.h>
#include <stdint.h>

/*
 * ASN1 Tags
 */
#define DRVCRYPT_ASN1_CONSTRUCTED  0x20
#define DRVCRYPT_ASN1_SEQUENCE	   0x10
#define DRVCRYPT_ASN1_OID	   0x06
#define DRVCRYPT_ASN1_NULL	   0x05
#define DRVCRYPT_ASN1_OCTET_STRING 0x04

/*
 * OID Top Level = first two Node (Standard and Registration-authority)
 *
 * iso(1) member-body(2)
 * iso(1) identified-organization(3)
 * joint-iso-itu-t(2) country(16)
 */
#define DRVCRYPT_OID_ISO_MEMBER_BODY "\x2a"
#define DRVCRYPT_OID_ISO_ID_ORG	     "\x2b"
#define DRVCRYPT_OID_ISO_ITU_COUNTRY "\x60"

/*
 * ISO Member body
 *
 * us(840)
 * us(840) rsadsi(113549)
 */
#define DRVCRYPT_OID_MB_US	  "\x86\x48"
#define DRVCRYPT_OID_MB_US_RSADSI DRVCRYPT_OID_MB_US "\x86\xF7\x0D"

/*
 * ISO Identified organization
 *
 * oiw(14)
 * oiw(14) secsig(3)
 */
#define DRVCRYPT_OID_IO_OIW	   "\x0e"
#define DRVCRYPT_OID_IO_OIW_SECSIG DRVCRYPT_OID_IO_OIW "\x03"

/*
 * ISO ITU OID
 *
 * organization(1)
 * organization(1) gov(101)
 */
#define DRVCRYPT_OID_ITU_ORG	 "\x01"
#define DRVCRYPT_OID_ITU_ORG_GOV DRVCRYPT_OID_ITU_ORG "\x65"

/*
 * Digest Algorithm
 *
 * digestAlgorithm(2)
 * csor(3) nistalgotrithm(4)
 */
#define DRVCRYPT_OID_DIGEST	      "\x02"
#define DRVCRYPT_OID_DIGEST_CSOR_NIST "\x03\x04"

/*
 * Definition of the Hash OID String
 *
 * id-md5 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5
 * }
 * id-sha1 OBJECT IDENTIFIER ::= {
 *   iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26
 * }
 * id-sha224 OBJECT IDENTIFIER ::= {
 *   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
 *   csor(3) nistalgorithm(4) hashalgs(2) 4
 * }
 * id-sha256 OBJECT IDENTIFIER ::= {
 *   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
 *   csor(3) nistalgorithm(4) hashalgs(2) 1
 * }
 * id-sha384 OBJECT IDENTIFIER ::= {
 *   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
 *   csor(3) nistalgorithm(4) hashalgs(2) 2
 * }
 * id-sha512 OBJECT IDENTIFIER ::= {
 *   joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
 *   csor(3) nistalgorithm(4) hashalgs(2) 3
 * }
 *
 */
#define DRVCRYPT_OID_ID_MD5                                                    \
	DRVCRYPT_OID_ISO_MEMBER_BODY DRVCRYPT_OID_MB_US_RSADSI                 \
		DRVCRYPT_OID_DIGEST "\x05"

#define DRVCRYPT_OID_ID_SHA1                                                   \
	DRVCRYPT_OID_ISO_ID_ORG DRVCRYPT_OID_IO_OIW_SECSIG DRVCRYPT_OID_DIGEST \
		"\x1a"

#define DRVCRYPT_OID_ID_SHA224                                                 \
	DRVCRYPT_OID_ISO_ITU_COUNTRY DRVCRYPT_OID_MB_US                        \
		DRVCRYPT_OID_ITU_ORG_GOV DRVCRYPT_OID_DIGEST_CSOR_NIST         \
			DRVCRYPT_OID_DIGEST "\x04"

#define DRVCRYPT_OID_ID_SHA256                                                 \
	DRVCRYPT_OID_ISO_ITU_COUNTRY DRVCRYPT_OID_MB_US                        \
		DRVCRYPT_OID_ITU_ORG_GOV DRVCRYPT_OID_DIGEST_CSOR_NIST         \
			DRVCRYPT_OID_DIGEST "\x01"

#define DRVCRYPT_OID_ID_SHA384                                                 \
	DRVCRYPT_OID_ISO_ITU_COUNTRY DRVCRYPT_OID_MB_US                        \
		DRVCRYPT_OID_ITU_ORG_GOV DRVCRYPT_OID_DIGEST_CSOR_NIST         \
			DRVCRYPT_OID_DIGEST "\x02"

#define DRVCRYPT_OID_ID_SHA512                                                 \
	DRVCRYPT_OID_ISO_ITU_COUNTRY DRVCRYPT_OID_MB_US                        \
		DRVCRYPT_OID_ITU_ORG_GOV DRVCRYPT_OID_DIGEST_CSOR_NIST         \
			DRVCRYPT_OID_DIGEST "\x03"

#define DRVCRYPT_OID_LEN(_id) (sizeof(_id) - 1)

/*
 * Definition of the ASN1 OID structure
 */
struct drvcrypt_oid {
	const char *asn1;	  /* OID ASN1 string */
	const size_t asn1_length; /* OID ASN1 string length */
};

/*
 * Hash OID constant array
 */
extern const struct drvcrypt_oid drvcrypt_hash_oid[];

/*
 * Return the Hash OID value registered in the Hash OID table.
 *
 * @algo	Hash algorithm identifier
 */
const struct drvcrypt_oid *drvcrypt_get_alg_hash_oid(uint32_t algo);

#endif /* __ASN1_OID_H__ */
