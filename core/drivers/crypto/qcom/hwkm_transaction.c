// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <assert.h>
#include <hwkm.h>
#include <hwkm_regs.h>
#include <io.h>
#include <kernel/delay.h>
#include <string.h>
#include <string_ext.h>

/*
 * Command packet format:
 * Each command starts with a CMD[0] operation-info word that encodes the
 * opcode, slot indices, flags, and total packet length. Subsequent words
 * carry the policy, BSVE, software context, and a CRC word (always 0 while
 * CRC checking is disabled).
 */

static_assert(HWKM_OP_NIST_KEYGEN == 0x0);
static_assert(HWKM_OP_SYSTEM_KDF == 0x1);
static_assert(HWKM_OP_KEY_WRAP_EXPORT == 0x3);
static_assert(HWKM_OP_KEY_UNWRAP_IMPORT == 0x4);
static_assert(HWKM_OP_KEY_SLOT_CLEAR == 0x5);
static_assert(HWKM_OP_KEY_SLOT_RDWR == 0x6);
static_assert(HWKM_OP_SET_TPKEY == 0x7);

#define HWKM_OPERATION_INFO_WORDS	1

/* Command and response formats. */

/* Shared macros: */

#define HWKM_KEY_POLICY_WORDS		2
#define HWKM_BSVE_WORDS			3
#define HWKM_KEY_BLOB_WORDS		17
#define HWKM_SOFTWARE_CONTEXT_WORDS	16
#define HWKM_KEY_RDWR_WORDS		8

static_assert(HWKM_KEY_BLOB_WORDS * sizeof(uint32_t) == HWKM_MAX_BLOB_SIZE);
static_assert(HWKM_SOFTWARE_CONTEXT_WORDS * sizeof(uint32_t) ==
	HWKM_MAX_CTX_SIZE);
static_assert(HWKM_KEY_RDWR_WORDS * sizeof(uint32_t) == HWKM_MAX_KEY_SIZE);

/*
 * HWKM_OP_NIST_KEYGEN - Generate a fresh key into a slot via hardware PRNG.
 *
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Policy.
 *   CMD[3] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_NIST_KEYGEN_RSP_ERR_IDX] = Error status.
 */
#define HWKM_OP_NIST_KEYGEN_CMD_WORDS	4	/* CMD[0] + policy + CRC. */
#define HWKM_OP_NIST_KEYGEN_RSP_WORDS	2	/* RSP[0:1]. */
#define HWKM_OP_NIST_KEYGEN_RSP_ERR_IDX	1

/*
 * HWKM_OP_SYSTEM_KDF - Derive a child key from a KDK slot via hardware KDF.
 *
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Policy.
 *   CMD[3] = BSVE[0] if bsve is enabled, 0 otherwise.
 *   CMD[4:5] = BSVE[1:2] only if bsve is enabled.
 *   CMD[n:n + m] = Software Context (SC), where n = 4 or 6 depending on BSVE,
 *                  and m is SC length.
 *   CMD[n + m + 1] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_SYSTEM_KDF_RSP_ERR_IDX] = Error status.
 */
/* CMD[0] + policy + BSVE[0] + CRC (minimum, excluding context). */
#define HWKM_OP_SYSTEM_KDF_CMD_WORDS	4
#define HWKM_OP_SYSTEM_KDF_RSP_WORDS	2	/* RSP[0:1]. */
#define HWKM_OP_SYSTEM_KDF_RSP_ERR_IDX	1

/*
 * HWKM_OP_KEY_WRAP_EXPORT - Encrypt a slot under a KWK/KSK and return the blob.
 *
 *   CMD[0] = Operation info.
 *   CMD[1:3] = BSVE.
 *   CMD[4] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *   RSP[HWKM_OP_KEY_WRAP_EXPORT_RSP_BLOB_IDX:
 *       HWKM_OP_KEY_WRAP_EXPORT_RSP_BLOB_IDX + HWKM_KEY_BLOB_WORDS - 1]
 *        = Wrapped Key Blob.
 */
/* CMD[0] + BSVE + CRC. */
#define HWKM_OP_KEY_WRAP_EXPORT_CMD_WORDS	5
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_WORDS	19	/* RSP[0:1] + blob. */
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_ERR_IDX	1
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_BLOB_IDX 2

/*
 * HWKM_OP_KEY_UNWRAP_IMPORT - Decrypt a wrapped blob and write the key
 *                             into a slot.
 *
 *   CMD[0] = Operation info.
 *   CMD[1:17] = Wrapped Key Blob.
 *   CMD[18] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_KEY_UNWRAP_IMPORT_RSP_ERR_IDX]    = Error status.
 */
/* CMD[0] + blob + CRC. */
#define HWKM_OP_KEY_UNWRAP_IMPORT_CMD_WORDS	19
#define HWKM_OP_KEY_UNWRAP_IMPORT_RSP_WORDS	2	/* RSP[0:1]. */
#define HWKM_OP_KEY_UNWRAP_IMPORT_RSP_ERR_IDX	1

/*
 * HWKM_OP_KEY_SLOT_CLEAR - Zeroize a slot and invalidate its policy word.
 *
 *   CMD[0] = Operation info.
 *   CMD[1] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_KEY_SLOT_CLEAR_RSP_ERR_IDX] = Error status
 */
#define HWKM_OP_KEY_SLOT_CLEAR_CMD_WORDS	2	/* CMD[0] + CRC. */
#define HWKM_OP_KEY_SLOT_CLEAR_RSP_WORDS	2	/* RSP[0:1]. */
#define HWKM_OP_KEY_SLOT_CLEAR_RSP_ERR_IDX	1

/*
 * HWKM_OP_KEY_SLOT_RDWR - Read or write raw key material for a SW_KEY slot.
 *
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Written policy (0 if read).
 *   CMD[3:10] = Written key value (0 if read).
 *   CMD[11] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_KEY_SLOT_RDWR_RSP_ERR_IDX] = Error status.
 *   RSP[HWKM_OP_KEY_SLOT_RDWR_RSP_POLICY_IDX:
 *       HWKM_OP_KEY_SLOT_RDWR_RSP_POLICY_IDX + HWKM_KEY_POLICY_WORDS - 1]
 *        = Read policy (0 if write).
 *   RSP[HWKM_OP_KEY_SLOT_RDWR_RSP_READ_KEY_IDX:
 *       HWKM_OP_KEY_SLOT_RDWR_RSP_READ_KEY_IDX + HWKM_KEY_RDWR_WORDS -1]
 *        = Read key value (0 if write).
 */
/* CMD[0] + policy + key + CRC. */
#define HWKM_OP_KEY_SLOT_RDWR_CMD_WORDS		12
/* RSP[0:1] + policy + key. */
#define HWKM_OP_KEY_SLOT_RDWR_RSP_WORDS		12
#define HWKM_OP_KEY_SLOT_RDWR_RSP_ERR_IDX	1
#define HWKM_OP_KEY_SLOT_RDWR_RSP_POLICY_IDX	2
#define HWKM_OP_KEY_SLOT_RDWR_RSP_READ_KEY_IDX	4

/*
 * HWKM_OP_SET_TPKEY - Install a slot as the active transport protection key.
 *
 *   CMD[0] = Operation info.
 *   CMD[1] = CRC (disabled).
 *
 *   RSP[0] = Unused.
 *   RSP[HWKM_OP_SET_TPKEY_RSP_ERR_IDX] = Error status.
 */
#define HWKM_OP_SET_TPKEY_CMD_WORDS	2	/* CMD[0] + CRC. */
#define HWKM_OP_SET_TPKEY_RSP_WORDS	2	/* RSP[0:1]. */
#define HWKM_OP_SET_TPKEY_RSP_ERR_IDX	1

/* PACK and UNPACK. */

/* Set one field of @reg to @val, positioned by @mask's lowest set bit. */
#define hwkm_pack(reg, val, mask) \
	((reg) = set_field_u32((reg), (mask), (val)))
/* Store the field of @reg selected by @mask, right-justified, into @dst. */
#define hwkm_unpack(dst, reg, mask) \
	((dst) = (typeof(dst))get_field_u32((reg), (mask)))

/* Operation info - HWKM_OPERATION_INFO_WORDS word. */
#define HWKM_OP_INFO_OP_MASK		GENMASK_32(3, 0)
#define HWKM_OP_INFO_SLOT1_DESC_MASK	GENMASK_32(12, 5)
#define HWKM_OP_INFO_SLOT2_DESC_MASK	GENMASK_32(20, 13)
#define HWKM_OP_INFO_OP_FLAG		BIT(21)
#define HWKM_OP_INFO_CONTEXT_LEN_MASK	GENMASK_32(26, 22)
#define HWKM_OP_INFO_LEN_MASK		GENMASK_32(31, 27)

/* Key policy - HWKM_KEY_POLICY_WORDS words. */
#define HWKM_KEY_POL_WRAP_WITH_TPKEY	BIT(2)
#define HWKM_KEY_POL_HW_DEST_MASK	GENMASK_32(6, 3)
#define HWKM_KEY_POL_SEC_LVL_MASK	GENMASK_32(10, 9)
#define HWKM_KEY_POL_SWAP_EXPORT	BIT(11)
#define HWKM_KEY_POL_WRAP_EXPORT	BIT(12)
#define HWKM_KEY_POL_KEY_TYPE_MASK	GENMASK_32(15, 13)
#define HWKM_KEY_POL_KDF_DEPTH_MASK	GENMASK_32(23, 16)
#define HWKM_KEY_POL_DECRYPT		BIT(24)
#define HWKM_KEY_POL_ENCRYPT		BIT(25)
#define HWKM_KEY_POL_ALG_MASK		GENMASK_32(31, 26)
#define HWKM_KEY_POL_KM_BY_TZ		BIT(0)
#define HWKM_KEY_POL_KM_BY_NSEC		BIT(1)
#define HWKM_KEY_POL_KM_BY_MODEM	BIT(2)
#define HWKM_KEY_POL_KM_BY_SPU		BIT(3)

/* Wrapping BSVE - HWKM_BSVE_WORDS words, word 0 only (words 1:2 reserved). */
#define HWKM_WRAP_BSVE_KEY_POL_VER	BIT(0)
#define HWKM_WRAP_BSVE_APPS_SEC		BIT(1)
#define HWKM_WRAP_BSVE_MSA_SEC		BIT(2)
#define HWKM_WRAP_BSVE_LCM_FUSE_ROW	BIT(3)
#define HWKM_WRAP_BSVE_BOOT_STAGE_OTP	BIT(4)

/* KDF BSVE - HWKM_BSVE_WORDS words. */
#define HWKM_KDF_BSVE_MKS		GENMASK_32(7, 0)
#define HWKM_KDF_BSVE_KEY_POL_VER	BIT(8)
#define HWKM_KDF_BSVE_APPS_SEC		BIT(9)
#define HWKM_KDF_BSVE_MSA_SEC		BIT(10)
#define HWKM_KDF_BSVE_LCM_FUSE_ROW	BIT(11)
#define HWKM_KDF_BSVE_BOOT_STAGE_OTP	BIT(12)
#define HWKM_KDF_BSVE_SWC		BIT(13)
#define HWKM_KDF_BSVE_CHILD_KEY_POL	BIT(14)
#define HWKM_KDF_BSVE_MKS_EN		BIT(15)

/*
 * hwkm_pack_op_info() - Pack the CMD[0] operation-info word.
 * @dst: Destination word.
 * @op: Opcode [3:0].
 * @slot1_desc: DKS or SKS depending on opcode.
 * @slot2_desc: KDK, KWK, or 0 depending on opcode.
 * @op_flag: Flag whose meaning depends on opcode.
 * @context_len: Software context length in words, KDF only.
 * @len: Total command length in words.
 */
static void hwkm_pack_op_info(uint32_t *dst, uint32_t op, uint8_t slot1_desc,
			      uint8_t slot2_desc, bool op_flag,
			      uint32_t context_len, uint32_t len)
{
	*dst = op & HWKM_OP_INFO_OP_MASK;

	hwkm_pack(*dst, slot1_desc, HWKM_OP_INFO_SLOT1_DESC_MASK);
	hwkm_pack(*dst, slot2_desc, HWKM_OP_INFO_SLOT2_DESC_MASK);
	hwkm_pack(*dst, op_flag, HWKM_OP_INFO_OP_FLAG);
	hwkm_pack(*dst, context_len, HWKM_OP_INFO_CONTEXT_LEN_MASK);
	hwkm_pack(*dst, len, HWKM_OP_INFO_LEN_MASK);
}

static void hwkm_pack_key_policy(uint32_t dst[HWKM_KEY_POLICY_WORDS],
				 const struct hwkm_key_policy *src)
{
	memset(dst, 0, HWKM_KEY_POLICY_WORDS * sizeof(uint32_t));
	/* Word 0: */
	hwkm_pack(dst[0], src->wrap_with_tpkey_allowed,
		  HWKM_KEY_POL_WRAP_WITH_TPKEY);
	hwkm_pack(dst[0], src->hw_destination, HWKM_KEY_POL_HW_DEST_MASK);
	hwkm_pack(dst[0], src->security_lvl, HWKM_KEY_POL_SEC_LVL_MASK);
	hwkm_pack(dst[0], src->swap_export_allowed, HWKM_KEY_POL_SWAP_EXPORT);
	hwkm_pack(dst[0], src->wrap_export_allowed, HWKM_KEY_POL_WRAP_EXPORT);
	hwkm_pack(dst[0], src->key_type, HWKM_KEY_POL_KEY_TYPE_MASK);
	hwkm_pack(dst[0], src->kdf_depth, HWKM_KEY_POL_KDF_DEPTH_MASK);
	hwkm_pack(dst[0], src->dec_allowed, HWKM_KEY_POL_DECRYPT);
	hwkm_pack(dst[0], src->enc_allowed, HWKM_KEY_POL_ENCRYPT);
	hwkm_pack(dst[0], src->alg_allowed, HWKM_KEY_POL_ALG_MASK);
	/* Word 1: */
	hwkm_pack(dst[1], src->km_by_tz_allowed, HWKM_KEY_POL_KM_BY_TZ);
	hwkm_pack(dst[1], src->km_by_nsec_allowed, HWKM_KEY_POL_KM_BY_NSEC);
	hwkm_pack(dst[1], src->km_by_modem_allowed, HWKM_KEY_POL_KM_BY_MODEM);
	hwkm_pack(dst[1], src->km_by_spu_allowed, HWKM_KEY_POL_KM_BY_SPU);
}

static void hwkm_unpack_key_policy(struct hwkm_key_policy *dst,
				   const uint32_t src[HWKM_KEY_POLICY_WORDS])
{
	memset(dst, 0, sizeof(*dst));
	/* Word 0: */
	hwkm_unpack(dst->wrap_with_tpkey_allowed, src[0],
		    HWKM_KEY_POL_WRAP_WITH_TPKEY);
	hwkm_unpack(dst->hw_destination, src[0], HWKM_KEY_POL_HW_DEST_MASK);
	hwkm_unpack(dst->security_lvl, src[0], HWKM_KEY_POL_SEC_LVL_MASK);
	hwkm_unpack(dst->swap_export_allowed, src[0], HWKM_KEY_POL_SWAP_EXPORT);
	hwkm_unpack(dst->wrap_export_allowed, src[0], HWKM_KEY_POL_WRAP_EXPORT);
	hwkm_unpack(dst->key_type, src[0], HWKM_KEY_POL_KEY_TYPE_MASK);
	hwkm_unpack(dst->kdf_depth, src[0], HWKM_KEY_POL_KDF_DEPTH_MASK);
	hwkm_unpack(dst->dec_allowed, src[0], HWKM_KEY_POL_DECRYPT);
	hwkm_unpack(dst->enc_allowed, src[0], HWKM_KEY_POL_ENCRYPT);
	hwkm_unpack(dst->alg_allowed, src[0], HWKM_KEY_POL_ALG_MASK);
	/* Word 1: */
	hwkm_unpack(dst->km_by_tz_allowed, src[1], HWKM_KEY_POL_KM_BY_TZ);
	hwkm_unpack(dst->km_by_nsec_allowed, src[1], HWKM_KEY_POL_KM_BY_NSEC);
	hwkm_unpack(dst->km_by_modem_allowed, src[1], HWKM_KEY_POL_KM_BY_MODEM);
	hwkm_unpack(dst->km_by_spu_allowed, src[1], HWKM_KEY_POL_KM_BY_SPU);
}

/* Leaves @dst zeroed (BSVE disabled) if @src->enabled is false. */
static void hwkm_pack_wrap_bsve(uint32_t dst[HWKM_BSVE_WORDS],
				const struct hwkm_bsve *src)
{
	memset(dst, 0, HWKM_BSVE_WORDS * sizeof(uint32_t));

	if (!src->enabled)
		return;

	hwkm_pack(dst[0], src->km_key_policy_ver_en,
		  HWKM_WRAP_BSVE_KEY_POL_VER);
	hwkm_pack(dst[0], src->km_apps_secure_en, HWKM_WRAP_BSVE_APPS_SEC);
	hwkm_pack(dst[0], src->km_msa_secure_en, HWKM_WRAP_BSVE_MSA_SEC);
	hwkm_pack(dst[0], src->km_lcm_fuse_en, HWKM_WRAP_BSVE_LCM_FUSE_ROW);
	hwkm_pack(dst[0], src->km_boot_stage_otp_en,
		  HWKM_WRAP_BSVE_BOOT_STAGE_OTP);
}

/* Leaves @dst zeroed (BSVE disabled) if @src->enabled is false. */
static void hwkm_pack_kdf_bsve(uint32_t dst[HWKM_BSVE_WORDS],
			       const struct hwkm_bsve *src, uint8_t mks)
{
	uint64_t digest = 0;

	memset(dst, 0, HWKM_BSVE_WORDS * sizeof(uint32_t));

	if (!src->enabled)
		return;

	digest = src->km_fuse_region_sha_digest_en;
	/* Word 0: */
	hwkm_pack(dst[0], mks, HWKM_KDF_BSVE_MKS);
	hwkm_pack(dst[0], src->km_key_policy_ver_en, HWKM_KDF_BSVE_KEY_POL_VER);
	hwkm_pack(dst[0], src->km_apps_secure_en, HWKM_KDF_BSVE_APPS_SEC);
	hwkm_pack(dst[0], src->km_msa_secure_en, HWKM_KDF_BSVE_MSA_SEC);
	hwkm_pack(dst[0], src->km_lcm_fuse_en, HWKM_KDF_BSVE_LCM_FUSE_ROW);
	hwkm_pack(dst[0], src->km_boot_stage_otp_en,
		  HWKM_KDF_BSVE_BOOT_STAGE_OTP);
	hwkm_pack(dst[0], src->km_swc_en, HWKM_KDF_BSVE_SWC);
	/* Digest bits [17:0] -> word 0 [31:14]. */
	dst[0] |= (uint32_t)(digest & GENMASK_64(17, 0)) << 14;
	/* Word 1: */
	/* Digest bits [49:18] -> word 1 [31:0]. */
	dst[1] = (uint32_t)((digest >> 18) & GENMASK_64(31, 0));
	/* Word 2: */
	/* Digest bits [63:50] -> word 2 [13:0]. */
	dst[2] |= (uint32_t)((digest >> 50) & GENMASK_64(13, 0));
	hwkm_pack(dst[2], src->km_child_key_policy_en,
		  HWKM_KDF_BSVE_CHILD_KEY_POL);
	hwkm_pack(dst[2], src->km_mks_en, HWKM_KDF_BSVE_MKS_EN);
}

/*
 * hwkm_reverse_bytes() - Reverse @len bytes of @buf in-place.
 *
 * The HWKM hardware stores and returns key material in the opposite byte order
 * to the canonical software representation. Apply this function before writing
 * a key into a command packet and after reading a key from a response packet.
 */
static void hwkm_reverse_bytes(uint8_t *buf, size_t len)
{
	size_t left = 0;
	size_t right = len - 1;

	assert(len > 0);

	while (left < right) {
		uint8_t tmp = buf[left];

		buf[left++] = buf[right];
		buf[right--] = tmp;
	}
}

/*
 * hwkm_reorder_kdf_ctx() - Reverse the context bytes in 8-byte chunks.
 *
 * To satisfy NIST SP800-108 KAT compliance the hardware expects the software
 * context to have its byte order swapped on each 8-byte (64-bit) boundary
 * before being written to the command packet.
 *
 * Example: 00 01 02 03 04 05 06 07  ->  07 06 05 04 03 02 01 00
 */
static void hwkm_reorder_kdf_ctx(uint8_t *buf, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i += sizeof(uint64_t))
		hwkm_reverse_bytes(buf + i, MIN(sizeof(uint64_t), len - i));
}

/* RUN TRANSACTION. */

#define HWKM_MASTER_MAX_RETRIES	100000U

static int hwkm_fifo_wait(vaddr_t base, uint32_t reg, uint32_t mask)
{
	uint32_t retries = 0;

	while (!io_read32_off_field(base, reg, mask)) {
		if (++retries > HWKM_MASTER_MAX_RETRIES)
			return HWKM_ERR_FIFO_TIMEOUT;
		udelay(10);
	}

	return HWKM_SUCCESS;
}

/*
 * master_run_transaction() - Submit one command packet to the master HWKM.
 * @cmd: Command packet words to write into the command FIFO.
 * @cmd_words: Number of 32-bit words in @cmd.
 * @rsp: Response buffer filled from the response FIFO.
 * @rsp_words: Number of 32-bit words expected in @rsp.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
static int master_run_transaction(const uint32_t *cmd, size_t cmd_words,
				  uint32_t *rsp, size_t rsp_words)
{
	struct hwkm_drv_ctx *ctx = NULL;
	int rc = HWKM_ERR_GENERIC;
	vaddr_t base = 0;
	size_t i = 0;

	if (!cmd || !cmd_words || !rsp || !rsp_words)
		return HWKM_ERR_INVALID_ARG;

	ctx = hwkm_get_context();
	if (!ctx)
		return HWKM_ERR_INVALID_ARG;

	base = ctx->base;

	/* Flush any stale command FIFO contents. */
	io_write32_off_field(base, HWKM_BANK0_KM_CTL,
			     HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR, 1);
	io_write32_off_field(base, HWKM_BANK0_KM_CTL,
			     HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR, 0);

	/* Clear stale error state from the previous transaction. */
	io_write32_off(base, HWKM_BANK0_KM_ESR,
		       io_read32_off(base, HWKM_BANK0_KM_ESR));

	/* Enable command processing. */
	io_write32_off_field(base, HWKM_BANK0_KM_CTL,
			     HWKM_BANK0_KM_CTL_CMD_ENABLE, 1);

	/* Confirm the FIFO clear bit has deasserted. */
	if (io_read32_off_field(base, HWKM_BANK0_KM_CTL,
				HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR))
		return HWKM_ERR_FIFO_NOT_EMPTY;

	/* Push the command packet one word at a time. */
	for (i = 0; i < cmd_words; i++) {
		rc = hwkm_fifo_wait(base, HWKM_BANK0_KM_STATUS,
				    HWKM_BANK0_KM_STATUS_CMD_AVAIL_SPACE);
		if (rc)
			return rc;

		io_write32_off(base, HWKM_BANK0_KM_CMD_FIFO, cmd[i]);
	}

	/* Pull the response packet one word at a time. */
	for (i = 0; i < rsp_words; i++) {
		rc = hwkm_fifo_wait(base, HWKM_BANK0_KM_STATUS,
				    HWKM_BANK0_KM_STATUS_RSP_AVAIL_DATA);
		if (rc)
			return rc;

		rsp[i] = io_read32_off(base, HWKM_BANK0_KM_RSP_FIFO);
	}

	/* The hardware must report completion after the response is read. */
	if (!io_read32_off_field(base, HWKM_BANK0_KM_IRQ_STATUS,
				 HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE))
		return HWKM_ERR_RSP_OVERFLOW;

	/* Acknowledge completion. */
	io_write32_off(base, HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE);

	return HWKM_SUCCESS;
}

static int run_transaction(const struct hwkm_transaction *t,
			   const uint32_t *cmd, size_t cmd_words,
			   uint32_t *rsp, size_t rsp_words)
{
	switch (t->hdl->dest) {
	case HWKM_KEY_DEST_KM_MASTER:
		return master_run_transaction(cmd, cmd_words, rsp, rsp_words);
	default:
		return HWKM_ERR_INVALID_DEST;
	}
}

/* Command handlers. */

static int hwkm_nist_keygen_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_NIST_KEYGEN_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_NIST_KEYGEN_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_NIST_KEYGEN, t->cmd.keygen.dks,
			  0, false, 0, ARRAY_SIZE(cmd));
	/* CMD[1:2]: */
	hwkm_pack_key_policy(&cmd[HWKM_OPERATION_INFO_WORDS],
			     &t->cmd.keygen.policy);

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_NIST_KEYGEN_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_system_kdf_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_SYSTEM_KDF_CMD_WORDS +
		     HWKM_BSVE_WORDS + HWKM_SOFTWARE_CONTEXT_WORDS] = { };
	uint32_t rsp[HWKM_OP_SYSTEM_KDF_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;
	size_t ctx_words = 0;
	size_t cmd_words = 0;
	size_t ctx_idx = 0;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	if (t->cmd.kdf.ctx_len > sizeof(t->cmd.kdf.ctx))
		return HWKM_ERR_INVALID_ARG;

	ctx_words = ROUNDUP_DIV(t->cmd.kdf.ctx_len, sizeof(uint32_t));
	ctx_idx = HWKM_OPERATION_INFO_WORDS + HWKM_KEY_POLICY_WORDS +
		  (t->cmd.kdf.bsve.enabled ? HWKM_BSVE_WORDS : 1);

	/* Total command length. */
	cmd_words = ctx_idx + ctx_words + 1 /* CRC */;
	if (cmd_words > ARRAY_SIZE(cmd))
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_SYSTEM_KDF, t->cmd.kdf.dks,
			  t->cmd.kdf.kdk, t->cmd.kdf.bsve.enabled, ctx_words,
			  /* incl. CRC, excl. context. */
			  ctx_idx + 1);
	/* CMD[1:2]: */
	hwkm_pack_key_policy(&cmd[HWKM_OPERATION_INFO_WORDS],
			     &t->cmd.kdf.policy);

	if (t->cmd.kdf.bsve.enabled) {
		/* CMD[3:5]: */
		hwkm_pack_kdf_bsve(&cmd[HWKM_OPERATION_INFO_WORDS +
					HWKM_KEY_POLICY_WORDS],
				   &t->cmd.kdf.bsve, t->cmd.kdf.mks);
	}

	if (t->cmd.kdf.ctx_len) {
		/* CMD[n:], if software context exists: */
		memcpy(&cmd[ctx_idx], t->cmd.kdf.ctx, t->cmd.kdf.ctx_len);
		hwkm_reorder_kdf_ctx((uint8_t *)&cmd[ctx_idx],
				     t->cmd.kdf.ctx_len);
	}

	rc = run_transaction(t, cmd, cmd_words, rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_SYSTEM_KDF_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_key_wrap_export_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_WRAP_EXPORT_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_KEY_WRAP_EXPORT, t->cmd.wrap.sks,
			  t->cmd.wrap.kwk, false, 0, ARRAY_SIZE(cmd));
	/* CMD[1:3]: */
	hwkm_pack_wrap_bsve(&cmd[HWKM_OPERATION_INFO_WORDS],
			    &t->cmd.wrap.bsve);

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS) {
		t->rsp.status = rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_ERR_IDX];
		/* On operation success, RSP[2:18]: */
		if (!t->rsp.status) {
			memcpy(t->rsp.wrap.wkb,
			       &rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_BLOB_IDX],
			       HWKM_MAX_BLOB_SIZE);
		}
	}

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_key_unwrap_import_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_UNWRAP_IMPORT_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_UNWRAP_IMPORT_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_KEY_UNWRAP_IMPORT,
			  t->cmd.unwrap.dks, t->cmd.unwrap.kwk, false, 0,
			  ARRAY_SIZE(cmd));
	/* CMD[1:17]: */
	memcpy(&cmd[HWKM_OPERATION_INFO_WORDS], t->cmd.unwrap.wkb,
	       HWKM_MAX_BLOB_SIZE);

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_KEY_UNWRAP_IMPORT_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_key_slot_clear_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_SLOT_CLEAR_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_SLOT_CLEAR_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_KEY_SLOT_CLEAR, t->cmd.clear.dks,
			  0, t->cmd.clear.is_double_key, 0, ARRAY_SIZE(cmd));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_KEY_SLOT_CLEAR_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_key_slot_rdwr_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_SLOT_RDWR_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_KEY_SLOT_RDWR, t->cmd.rdwr.slot,
			  0, t->cmd.rdwr.is_write, 0, ARRAY_SIZE(cmd));

	if (t->cmd.rdwr.is_write) {
		/* CMD[1:2]: */
		hwkm_pack_key_policy(&cmd[HWKM_OPERATION_INFO_WORDS],
				     &t->cmd.rdwr.policy);
		/* CMD[3:10]: */
		memcpy(&cmd[HWKM_OPERATION_INFO_WORDS + HWKM_KEY_POLICY_WORDS],
		       t->cmd.rdwr.key, HWKM_MAX_KEY_SIZE);
		hwkm_reverse_bytes((uint8_t *)&cmd[HWKM_OPERATION_INFO_WORDS +
						   HWKM_KEY_POLICY_WORDS],
				   HWKM_MAX_KEY_SIZE);
	}

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS) {
		t->rsp.status = rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_ERR_IDX];
		if (!t->cmd.rdwr.is_write && !t->rsp.status) {
			uint32_t *rsp_policy =
				&rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_POLICY_IDX];

			/* RSP[2:3]: */
			hwkm_unpack_key_policy(&t->rsp.rdwr.policy, rsp_policy);
			/* RSP[4:11]: */
			memcpy(t->rsp.rdwr.key,
			       &rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_READ_KEY_IDX],
			       HWKM_MAX_KEY_SIZE);
			hwkm_reverse_bytes(t->rsp.rdwr.key, HWKM_MAX_KEY_SIZE);
		}
	}

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_set_tpkey_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_SET_TPKEY_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_SET_TPKEY_RSP_WORDS] = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	if (t->hdl->dest != HWKM_KEY_DEST_KM_MASTER)
		return HWKM_ERR_INVALID_DEST;

	/* CMD[0]: */
	hwkm_pack_op_info(&cmd[0], HWKM_OP_SET_TPKEY, t->cmd.set_tpkey.sks,
			  0, false, 0, ARRAY_SIZE(cmd));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_SET_TPKEY_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

static int hwkm_transaction_dispatch(struct hwkm_transaction *t)
{
	switch (t->cmd.op) {
	case HWKM_OP_NIST_KEYGEN:
		return hwkm_nist_keygen_handle(t);
	case HWKM_OP_SYSTEM_KDF:
		return hwkm_system_kdf_handle(t);
	case HWKM_OP_KEY_WRAP_EXPORT:
		return hwkm_key_wrap_export_handle(t);
	case HWKM_OP_KEY_UNWRAP_IMPORT:
		return hwkm_key_unwrap_import_handle(t);
	case HWKM_OP_KEY_SLOT_CLEAR:
		return hwkm_key_slot_clear_handle(t);
	case HWKM_OP_KEY_SLOT_RDWR:
		return hwkm_key_slot_rdwr_handle(t);
	case HWKM_OP_SET_TPKEY:
		return hwkm_set_tpkey_handle(t);
	default:
		return HWKM_ERR_NOT_SUPPORTED;
	}
}

/* Command queue. */

int hwkm_handle_init(struct hwkm_handle *hdl, enum hwkm_key_destination dest)
{
	switch (dest) {
	case HWKM_KEY_DEST_KM_MASTER:
		break;
	default:
		return HWKM_ERR_INVALID_DEST;
	}

	hdl->dest = dest;
	STAILQ_INIT(&hdl->queue);

	return HWKM_SUCCESS;
}

int hwkm_enqueue(struct hwkm_handle *hdl, struct hwkm_transaction *t)
{
	if (!t)
		return HWKM_ERR_INVALID_ARG;

	if (t->hdl)
		return HWKM_ERR_INVALID_ARG;

	t->hdl = hdl;
	STAILQ_INSERT_TAIL(&hdl->queue, t, link);

	return HWKM_SUCCESS;
}

/*
 * hwkm_enqueue_many() - Enqueue multiple transactions on one handle.
 * @hdl: Handle that owns the queue.
 * @num_t: Number of transactions in @trans.
 * @trans: Array of transaction pointers to enqueue in FIFO order.
 *
 * Enqueues all transactions in @trans onto @hdl using hwkm_enqueue().
 * If enqueueing any transaction fails, all transactions already queued by
 * this call are removed again and their ownership is cleared, so the caller
 * sees all-or-nothing behavior.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
int hwkm_enqueue_many(struct hwkm_handle *hdl, size_t num_t,
		      struct hwkm_transaction *const trans[])
{
	int rc = HWKM_ERR_GENERIC;
	size_t i = 0;

	if (!hdl || (num_t && !trans))
		return HWKM_ERR_INVALID_ARG;

	for (i = 0; i < num_t; i++) {
		rc = hwkm_enqueue(hdl, trans[i]);
		if (rc)
			goto rollback;
	}

	return HWKM_SUCCESS;

rollback:
	while (i > 0) {
		struct hwkm_transaction *t = trans[--i];

		/* Release the ownership. */
		STAILQ_REMOVE(&hdl->queue, t, hwkm_transaction, link);
		t->hdl = NULL;
	}

	return rc;
}

/*
 * hwkm_run_cmd_queue() - Execute queued transactions.
 * @hdl: Handle containing queued transactions
 *
 * Executes all transactions queued on @hdl in FIFO order by calling
 * hwkm_transaction_dispatch() for each transaction. Execution stops at the
 * first error and that error is returned to the caller.
 *
 * On return, transactions that were processed are removed from the queue and
 * their ownership is cleared (to be reused).
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
int hwkm_run_cmd_queue(struct hwkm_handle *hdl)
{
	struct hwkm_transaction *t = NULL;
	int rc = HWKM_SUCCESS;

	while (!STAILQ_EMPTY(&hdl->queue)) {
		t = STAILQ_FIRST(&hdl->queue);
		rc = hwkm_transaction_dispatch(t);
		/* Release the ownership. */
		STAILQ_REMOVE_HEAD(&hdl->queue, link);
		t->hdl = NULL;

		if (rc != HWKM_SUCCESS)
			break;
	}

	return rc;
}
