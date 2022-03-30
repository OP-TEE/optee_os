/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __TPM2_H__
#define __TPM2_H__

#include <stdint.h>
#include <types_ext.h>
#include <util.h>

/* Algorithm Registry */
#define EFI_TCG2_BOOT_HASH_ALG_SHA1	BIT(0)
#define EFI_TCG2_BOOT_HASH_ALG_SHA256	BIT(1)
#define EFI_TCG2_BOOT_HASH_ALG_SHA384	BIT(2)
#define EFI_TCG2_BOOT_HASH_ALG_SHA512	BIT(3)
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256	BIT(4)

/* TPM2_ST Structure Tags */
#define TPM2_ST_RSP_COMMAND	U(0x00C4)
#define TPM2_ST_NULL		U(0X8000)
#define TPM2_ST_NO_SESSIONS	U(0x8001)
#define TPM2_ST_SESSIONS	U(0x8002)

/* TPM2_SU Constants Shutdown and startup modes */
#define TPM2_SU_CLEAR		U(0x0000)
#define TPM2_SU_STATE		U(0x0001)

/* Command Codes */
#define	TPM2_CC_NV_WRITE	U(0x00000137)
#define	TPM2_CC_SELFTEST	U(0x00000143)
#define TPM2_CC_STARTUP		U(0x00000144)
#define	TPM2_CC_NV_READ		U(0x0000014E)
#define	TPM2_CC_GET_CAPABILITY  U(0x0000017A)
#define	TPM2_CC_PCR_READ	U(0x0000017E)
#define	TPM2_CC_PCR_EXTEND	U(0x00000182)

/* Table 22 TPM2_CAP constants */
#define TPM2_CAP_PCRS		U(0x00000005)
#define TPM2_CAP_TPM_PROPERTIES	U(0x00000006)

/* Table 23 TPM2_PT constants */
#define TPM2_PT_NONE		U(0x00000000)
#define TPM2_PT_GROUP		U(0x00000100)
#define TPM2_PT_FIXED		(TPM2_PT_GROUP * 1)
#define TPM2_PT_PCR_COUNT	(TPM2_PT_FIXED + 18)
#define TPM2_PT_PCR_SELECT_MIN	(TPM2_PT_FIXED + 19)

/* Table 28 TPM_RH constants */
#define TPM_RS_PW		U(0x40000009)

/* TPM_ALG_ID table 19 Part2 Structures */
#define TPM2_ALG_SHA1		U(0x0004)
#define TPM2_ALG_SHA256		U(0x000B)
#define TPM2_ALG_SHA384		U(0x000C)
#define TPM2_ALG_SHA512		U(0x000D)

/* Section 4.2 - TSS_Overview_Common_v1_r10_pub09232021.pdf */

/* ABI Constants */
#define TPM2_SHA_DIGEST_SIZE		20
#define TPM2_SHA1_DIGEST_SIZE		20
#define TPM2_SHA256_DIGEST_SIZE		32
#define TPM2_SHA384_DIGEST_SIZE		48
#define TPM2_SHA512_DIGEST_SIZE		64
#define TPM2_SM3_256_DIGEST_SIZE	32

/* The following set of ABI constants were chosen by the TSS Working Group.
 * They represent reasonable, future-proof values.
 */
#define TPM2_NUM_PCR_BANKS	16
#define TPM2_MAX_PCRS		32
#define TPM2_PCR_SELECT_MAX	((TPM2_MAX_PCRS + 7) / 8)

/* Table 78 - Definition of TPMU_HA Union */
union tpmu_ha {
	uint8_t sha[TPM2_SHA_DIGEST_SIZE];
	uint8_t sha1[TPM2_SHA1_DIGEST_SIZE];
	uint8_t sha256[TPM2_SHA256_DIGEST_SIZE];
	uint8_t sha384[TPM2_SHA384_DIGEST_SIZE];
	uint8_t sha512[TPM2_SHA512_DIGEST_SIZE];
	uint8_t sm3_256[TPM2_SM3_256_DIGEST_SIZE];
};

/* Table 79 - Definition of TPMT_HA Structure */
struct tpmt_ha {
	uint16_t hash_alg;
	union tpmu_ha digest;
} __packed;

/* Table 110 TPML_DIGEST_VALUES */
struct tpml_digest_values {
	uint32_t count;
	struct tpmt_ha digests[TPM2_NUM_PCR_BANKS];
} __packed;

/* Table 80 - Definition of TPM2B_DIGEST Structure */
struct tpm2b_digest {
	uint16_t size;
	uint8_t buffer[sizeof(union tpmu_ha)];
} __packed;

/* Table 109 - Definition of TPML_DIGEST Structure */
struct tpml_digest {
	uint32_t count;
	struct tpm2b_digest digest[8];
} __packed;

/* Table 93 - Definition of TPMS_PCR_SELECTION Structure */
struct tpms_pcr_selection  {
	uint16_t hash;
	uint8_t size_of_select;
	uint8_t pcr_select[TPM2_PCR_SELECT_MAX];
} __packed;

/* Table 111 - Definition of TPML_PCR_SELECTION Structure */
struct tpml_pcr_selection {
	uint32_t count;
	struct tpms_pcr_selection pcr_selections[TPM2_NUM_PCR_BANKS];
} __packed;

/* Table 101 TPMS_TAGGED_PROPERTY */
struct tpms_tagged_property {
	uint32_t property;
	uint32_t value;
} __packed;

/* Table 113 TPML_TAGGED_TPM_PROPERTY */
struct tpml_tagged_tpm_property {
	uint32_t count;
	struct tpms_tagged_property tpm_property[];
} __packed;

/* Table 109 TPMU_CAPABILITIES Union */
union tpmu_capabilities {
	/*
	 * Non exhaustive. Only added the structs needed for our
	 * current code
	 */
	struct tpml_pcr_selection assigned_pcr;
	struct tpml_tagged_tpm_property tpm_properties;
} __packed;

/* Table 119 TPMS_CAPABILITY_DATA Structure */
struct tpms_capability_data {
	uint32_t capability;
	union tpmu_capabilities data;
} __packed;

struct tpms_auth_command {
	uint32_t handle;
	struct tpm2b_digest nonce;
	uint8_t session_attributes;
	struct tpm2b_digest hmac;
} __packed;

/*
 * Send a TPM2_Startup command
 *
 * @mode - TPM startup mode
 *	   It is one of TPM2_SU_CLEAR or TPM2_SU_STATE
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_startup(uint16_t mode);

/*
 * Send a TPM2_SelfTest command
 *
 * @full - 1 if full test needs to be performed
 *	   0 if only test of untested functions required
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_selftest(uint8_t full);

/*
 * Get TPM capabilities by sending a TPM2_GetCapability command
 *
 * @capability - Capability group selection of type TPM_CAP
 * @property - Property associated with the capability
 * @prop_cnt - Number of properties in indicated type
 * @buf - Returns the content of TPMU_CAPABILITIES from response buffer
 *	(Part of TPMS_CAPABILITY_DATA Structure retrned in response)
 * @buf_len - Size of the content returned
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_get_capability(uint32_t capability, uint32_t property,
				     uint32_t prop_cnt, void *buf,
				     uint32_t *buf_len);

/*
 * Read the PCR by sending a TPM2_PCR_Read command
 *
 * @pcr_idx - Index of the PCR to read
 * @alg - Hash algorithm (Bank) associated with PCR
 * @digest - Output buffer to return content of PCR
 * @digest_len - Size of the content read
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_pcr_read(uint8_t pcr_idx, uint16_t alg, void *digest,
			       uint32_t *digest_len);

/*
 * Extend the PCR by sending a TPM2_PCR_Extend command
 *
 * @pcr_idx - index of the PCR to be extended
 * @alg - Hash algorithm (Bank) associated with PCR
 * @digest - Input buffer with content to be extended
 * @digest_len - Size of the content
 *
 * @return - tpm2_result
 */
enum tpm2_result tpm2_pcr_extend(uint8_t pcr_idx, uint16_t alg, void *digest,
				 uint32_t digest_len);

/*
 * Get hash length corresponding to TPM algorithm
 *
 * @alg - TPM2 hash algorithm ID, on of TPM2_ALG_*
 *
 * @return - hash length or 0 if algorithm not supported
 */
static inline uint32_t tpm2_get_alg_len(uint16_t alg)
{
	switch (alg) {
	case TPM2_ALG_SHA1:
		return TPM2_SHA1_DIGEST_SIZE;
	case TPM2_ALG_SHA256:
		return TPM2_SHA256_DIGEST_SIZE;
	case TPM2_ALG_SHA384:
		return TPM2_SHA384_DIGEST_SIZE;
	case TPM2_ALG_SHA512:
		return TPM2_SHA512_DIGEST_SIZE;
	default:
		return 0;
	}
}

/*
 * Get TCG hash mask for TPM algorithm
 *
 * @alg - TPM2 hash algorithm ID, on of TPM2_ALG_*
 *
 * @return - TCG hashing algorithm bitmaps or 0 if algorithm not supported
 */
static inline uint32_t tpm2_alg_to_tcg_mask(uint16_t alg)
{
	switch (alg) {
	case TPM2_ALG_SHA1:
		return EFI_TCG2_BOOT_HASH_ALG_SHA1;
	case TPM2_ALG_SHA256:
		return EFI_TCG2_BOOT_HASH_ALG_SHA256;
	case TPM2_ALG_SHA384:
		return EFI_TCG2_BOOT_HASH_ALG_SHA384;
	case TPM2_ALG_SHA512:
		return EFI_TCG2_BOOT_HASH_ALG_SHA512;
	default:
		return 0;
	}
}

#endif	/* __TPM2_H__ */
