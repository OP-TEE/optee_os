/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    drvcrypt_asn1_oid.h
 *
 * @brief   Definition of the cryptographic algorthim's OID in the
 *          ASN1 String format.
 *          Definition of the ASN1 DER tags.
 * (<a href="http://csrc.nist.gov/groups/ST/crypto_apps_infra/
 * csor/algorithms.html">Computer Security Objects Register</a>
 *
 */
#ifndef __ASN1_OID_H__
#define __ASN1_OID_H__

/* Global includes */
#include <stdint.h>

/* Driver Crypto includes */
#include <drvcrypt_hash.h>

/*
 * ASN1 Tags
 */
#define ASN1_CONSTRUCTED        0x20
#define ASN1_SEQUENCE           0x10
#define ASN1_OID                0x06
#define ASN1_NULL               0x05
#define ASN1_OCTET_STRING       0x04

/*
 * OID Top Level = first two Node (Standard and Registration-authority)
 */
#define OID_ISO_MEMBER_BODY      "\x2a"  // iso(1) member-body(2)
#define OID_ISO_ID_ORG           "\x2b"  // iso(1) identified-organization(3)
#define OID_ISO_ITU_COUNTRY      "\x60"  // joint-iso-itu-t(2) country(16)

/*
 * ISO Member body
 */
#define OID_MB_US                "\x86\x48"     // us(840)
#define OID_MB_US_RSADSI         OID_MB_US "\x86\x48" // us(840) rsadsi(113549)


/*
 * ISO Identified organization
 */
#define OID_IO_OIW               "\x0e"            // oiw(14)
#define OID_IO_OIW_SECSIG        OID_IO_OIW "\x03" // oiw(14) secsig(3)

/*
 * ISO ITU OID
 */
#define OID_ITU_ORG              "\x01"             // organization(1)
#define OID_ITU_ORG_GOV          OID_ITU_ORG "\x65" // organization(1) gov(101)

/*
 * Digest Algorithm
 */
#define OID_DIGEST               "\x02"     // digestAlgorithm(2)
#define OID_DIGEST_CSOR_NIST     "\x03\x04" // csor(3) nistalgotrithm(4)

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
#define OID_ID_MD5	OID_ISO_MEMBER_BODY OID_MB_US_RSADSI \
			OID_DIGEST "\x05"

#define OID_ID_SHA1	OID_ISO_ID_ORG OID_IO_OIW_SECSIG \
			OID_DIGEST "\x1a"

#define OID_ID_SHA224	OID_ISO_ITU_COUNTRY OID_MB_US \
			OID_ITU_ORG_GOV OID_DIGEST_CSOR_NIST OID_DIGEST "\x04"

#define OID_ID_SHA256	OID_ISO_ITU_COUNTRY OID_MB_US \
			OID_ITU_ORG_GOV OID_DIGEST_CSOR_NIST OID_DIGEST "\x01"

#define OID_ID_SHA384	OID_ISO_ITU_COUNTRY OID_MB_US \
			OID_ITU_ORG_GOV OID_DIGEST_CSOR_NIST OID_DIGEST "\x02"

#define OID_ID_SHA512	OID_ISO_ITU_COUNTRY OID_MB_US \
			OID_ITU_ORG_GOV OID_DIGEST_CSOR_NIST OID_DIGEST "\x03"

/**
 * @brief   OID Macro defining a nxpcrypt_oid ASN1 entry
 */
#define OID_DEF(id)     {id, (sizeof(id) - 1)}

/**
 * @brief   Definition of the ASN1 OID structure
 */
struct drvcrypt_oid {
	const char    *asn1;        ///< OID ASN1 string
	const uint8_t asn1_length;  ///< OID ASN1 string length
};

/**
 * @brief   Hash OID constant array
 */
extern const struct drvcrypt_oid drvcrypt_hash_oid[MAX_HASH_SUPPORTED + 1];

#endif /* __ASN1_OID_H__ */


