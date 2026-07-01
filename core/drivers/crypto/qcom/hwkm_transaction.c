// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <assert.h>
#include <hwkm.h>
#include <hwkm_regs.h>
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

struct hwkm_operation_info {
	uint32_t op:4;		/* [3:0] opcode. */
	uint32_t irq_en:1;	/* [4] always 0 (polling mode). */
	uint32_t slot1_desc:8;	/* [12:5] DKS or SKS depending on opcode. */
	uint32_t slot2_desc:8;	/* [20:13] KDK, KWK, or 0. */
	uint32_t op_flag:1;	/* [21] flag depending on opcode. */
	uint32_t context_len:5;	/* [26:22] SW context length (KDF only). */
	uint32_t len:5;		/* [31:27] total cmd words. */
} __packed;

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
 *   RSP[HWKM_OP_KEY_WRAP_EXPORT_RSP_WRAPPED_KEY_IDX:
 *       HWKM_OP_KEY_WRAP_EXPORT_RSP_WRAPPED_KEY_IDX + HWKM_KEY_BLOB_WORDS - 1]
 *        = Wrapped Key Blob.
 */
/* CMD[0] + BSVE + CRC. */
#define HWKM_OP_KEY_WRAP_EXPORT_CMD_WORDS	5
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_WORDS	19	/* RSP[0:1] + blob. */
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_ERR_IDX	1
#define HWKM_OP_KEY_WRAP_EXPORT_RSP_WRAPPED_KEY_IDX 2

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

/* Size HWKM_KEY_POLICY_WORDS words. */
struct hwkm_hw_key_policy {
	uint32_t dbg_qfprom_key_rd_iv_sel:1;		/* [0] */
	uint32_t reserved0:1;				/* [1] */
	uint32_t wrap_with_tpkey:1;			/* [2] */
	uint32_t hw_destination:4;			/* [3:6] */
	uint32_t reserved1:1;				/* [7] */
	uint32_t propagate_sec_level_to_child_keys:1;	/* [8] */
	uint32_t security_level:2;			/* [9:10] */
	uint32_t swap_export_allowed:1;			/* [11] */
	uint32_t wrap_export_allowed:1;			/* [12] */
	uint32_t key_type:3;				/* [13:15] */
	uint32_t kdf_depth:8;				/* [16:23] */
	uint32_t decrypt_allowed:1;			/* [24] */
	uint32_t encrypt_allowed:1;			/* [25] */
	uint32_t alg_allowed:6;				/* [26:31] */
	uint32_t key_management_by_tz_secure_allowed:1;	/* [32] */
	uint32_t key_management_by_nonsecure_allowed:1;	/* [33] */
	uint32_t key_management_by_modem_allowed:1;	/* [34] */
	uint32_t key_management_by_spu_allowed:1;	/* [35] */
	uint32_t reserved2:28;				/* [36:63] */
} __packed;

/* Size HWKM_BSVE_WORDS words. */
struct hwkm_hw_kdf_bsve {
	uint32_t mks:8;					/* [7:0] */
	uint32_t key_policy_version_en:1;		/* [8] */
	uint32_t apps_secure_en:1;			/* [9] */
	uint32_t msa_secure_en:1;			/* [10] */
	uint32_t lcm_fuse_row_en:1;			/* [11] */
	uint32_t boot_stage_otp_en:1;			/* [12] */
	uint32_t swc_en:1;				/* [13] */
	uint64_t fuse_region_sha_digest_en:64;		/* [77:14] */
	uint32_t child_key_policy_en:1;			/* [78] */
	uint32_t mks_en:1;				/* [79] */
	uint32_t reserved:16;				/* [95:80] */
} __packed;

/* Size HWKM_BSVE_WORDS words. */
struct hwkm_hw_wrapping_bsve {
	uint32_t key_policy_version_en:1;	/* [0] */
	uint32_t apps_secure_en:1;		/* [1] */
	uint32_t msa_secure_en:1;		/* [2] */
	uint32_t lcm_fuse_row_en:1;		/* [3] */
	uint32_t boot_stage_otp_en:1;		/* [4] */
	uint32_t reserved0:27;			/* [31:5] */
	uint32_t reserved1:32;			/* [63:32] */
	uint32_t reserved2:32;			/* [95:64] */
} __packed;

/**
 * hwkm_pack_key_policy() - Pack a software key policy into hardware format.
 * @dst: Destination hardware policy structure.
 * @src: Source software policy.
 *
 * Fill @dst from @src using the HWKM hardware policy encoding.
 * Fields not represented in struct hwkm_key_policy are cleared.
 */
static void hwkm_pack_key_policy(struct hwkm_hw_key_policy *dst,
				 const struct hwkm_key_policy *src)
{
	memset(dst, 0, sizeof(*dst));

	dst->wrap_with_tpkey = !!src->wrap_with_tpkey_allowed;
	dst->hw_destination = (uint32_t)src->hw_destination;
	dst->security_level = (uint32_t)src->security_lvl;
	dst->swap_export_allowed = !!src->swap_export_allowed;
	dst->wrap_export_allowed = !!src->wrap_export_allowed;
	dst->key_type = (uint32_t)src->key_type;
	dst->kdf_depth = src->kdf_depth;
	dst->decrypt_allowed = !!src->dec_allowed;
	dst->encrypt_allowed = !!src->enc_allowed;
	dst->alg_allowed = (uint32_t)src->alg_allowed;
	dst->key_management_by_tz_secure_allowed = !!src->km_by_tz_allowed;
	dst->key_management_by_nonsecure_allowed = !!src->km_by_nsec_allowed;
	dst->key_management_by_modem_allowed = !!src->km_by_modem_allowed;
	dst->key_management_by_spu_allowed = !!src->km_by_spu_allowed;
}

/**
 * hwkm_unpack_key_policy() - Unpack a hardware key policy into software form.
 * @dst: Destination software policy.
 * @src: Source hardware policy structure.
 *
 * Decode @src from the HWKM hardware policy format into @dst.
 * Fields not represented in struct hwkm_key_policy are ignored.
 */
static void hwkm_unpack_key_policy(struct hwkm_key_policy *dst,
				   const struct hwkm_hw_key_policy *src)
{
	memset(dst, 0, sizeof(*dst));

	dst->wrap_with_tpkey_allowed = !!src->wrap_with_tpkey;
	dst->hw_destination = (enum hwkm_key_destination)src->hw_destination;
	dst->security_lvl = (enum hwkm_key_security_lvl)src->security_level;
	dst->swap_export_allowed = !!src->swap_export_allowed;
	dst->wrap_export_allowed = !!src->wrap_export_allowed;
	dst->key_type = (enum hwkm_key_type)src->key_type;
	dst->kdf_depth = (uint8_t)src->kdf_depth;
	dst->dec_allowed = !!src->decrypt_allowed;
	dst->enc_allowed = !!src->encrypt_allowed;
	dst->alg_allowed = (enum hwkm_algo)src->alg_allowed;
	dst->km_by_tz_allowed = !!src->key_management_by_tz_secure_allowed;
	dst->km_by_nsec_allowed = !!src->key_management_by_nonsecure_allowed;
	dst->km_by_modem_allowed = !!src->key_management_by_modem_allowed;
	dst->km_by_spu_allowed = !!src->key_management_by_spu_allowed;
}

/**
 * hwkm_pack_wrapping_bsve() - Pack wrapping BSVE settings into hardware format.
 * @dst: Destination hardware BSVE structure.
 * @src: Source BSVE settings.
 *
 * Fill @dst with the wrapping-BSVE encoding derived from @src. If BSVE is
 * disabled, @dst is cleared and no fields are set.
 */
static void hwkm_pack_wrapping_bsve(struct hwkm_hw_wrapping_bsve *dst,
				    const struct hwkm_bsve *src)
{
	memset(dst, 0, sizeof(*dst));

	if (!src->enabled)
		return;

	dst->key_policy_version_en = !!src->km_key_policy_ver_en;
	dst->apps_secure_en = !!src->km_apps_secure_en;
	dst->msa_secure_en = !!src->km_msa_secure_en;
	dst->lcm_fuse_row_en = !!src->km_lcm_fuse_en;
	dst->boot_stage_otp_en = !!src->km_boot_stage_otp_en;
}

/**
 * hwkm_pack_kdf_bsve() - Pack KDF BSVE settings into hardware format.
 * @dst: Destination hardware BSVE structure.
 * @src: Source BSVE settings.
 * @mks: Mixing key selector value.
 *
 * Fill @dst with the KDF-BSVE encoding derived from @src and @mks. If BSVE is
 * disabled, @dst is cleared and no fields are set.
 */
static void hwkm_pack_kdf_bsve(struct hwkm_hw_kdf_bsve *dst,
			       const struct hwkm_bsve *src,
			       uint8_t mks)
{
	memset(dst, 0, sizeof(*dst));

	if (!src->enabled)
		return;

	dst->mks = mks;
	dst->key_policy_version_en = !!src->km_key_policy_ver_en;
	dst->apps_secure_en = !!src->km_apps_secure_en;
	dst->msa_secure_en = !!src->km_msa_secure_en;
	dst->lcm_fuse_row_en = !!src->km_lcm_fuse_en;
	dst->boot_stage_otp_en = !!src->km_boot_stage_otp_en;
	dst->swc_en = !!src->km_swc_en;
	dst->fuse_region_sha_digest_en = src->km_fuse_region_sha_digest_en;
	dst->child_key_policy_en = !!src->km_child_key_policy_en;
	dst->mks_en = !!src->km_mks_en;
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

/**
 * hwkm_fifo_wait() - Poll a FIFO status field until it is non-zero.
 * @base: HWKM MMIO base.
 * @reg: Status register offset.
 * @mask: Field mask.
 * @shift: Field shift.
 *
 * Return: HWKM_SUCCESS when the field becomes non-zero, or
 *         HWKM_ERR_FIFO_TIMEOUT if the field does not become non-zero within
 *         HWKM_MASTER_MAX_RETRIES attempts.
 */
static int hwkm_fifo_wait(vaddr_t base, uint32_t reg,
			  uint32_t mask, uint32_t shift)
{
	uint32_t retries = 0;

	while (!hwkm_reg_get_field(base, reg, mask, shift)) {
		if (++retries > HWKM_MASTER_MAX_RETRIES)
			return HWKM_ERR_FIFO_TIMEOUT;
		udelay(10);
	}

	return HWKM_SUCCESS;
}

/**
 * master_run_transaction() - Submit one command packet to the master HWKM.
 * @cmd: Command packet words to write into the command FIFO.
 * @cmd_words: Number of 32-bit words in @cmd.
 * @rsp: Response buffer filled from the response FIFO.
 * @rsp_words: Number of 32-bit words expected in @rsp.
 *
 * Step by step:
 *   1. Fetch the driver context and resolve the HWKM MMIO base.
 *   2. Pulse CMD_FIFO_CLEAR to flush any stale command FIFO contents.
 *   3. Clear stale ESR bits from the previous transaction.
 *   4. Enable command processing in BANK0_KM_CTL.
 *   5. Verify that CMD_FIFO_CLEAR has deasserted, otherwise the FIFO did not
 *      drain correctly.
 *   6. For each command word, poll CMD_FIFO_AVAIL_SPACE until space is
 *      available or a timeout is reached, then write the word to
 *      HWKM_BANK0_KM_CMD_FIFO.
 *   7. For each response word, poll RSP_FIFO_AVAIL_DATA until data is
 *      available or a timeout is reached, then read the word from
 *      HWKM_BANK0_KM_RSP_FIFO.
 *   8. Verify that CMD_DONE is set, which indicates the command completed and
 *      the full response was produced.
 *   9. Clear CMD_DONE before returning.
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
	hwkm_reg_set_field(base, HWKM_BANK0_KM_CTL,
			   HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR,
			   HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR_SHIFT, 1);
	hwkm_reg_set_field(base, HWKM_BANK0_KM_CTL,
			   HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR,
			   HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR_SHIFT, 0);

	/* Clear stale error state from the previous transaction. */
	HWKM_REG_WRITE(base, HWKM_BANK0_KM_ESR,
		       HWKM_REG_READ(base, HWKM_BANK0_KM_ESR));

	/* Enable command processing. */
	hwkm_reg_set_field(base, HWKM_BANK0_KM_CTL,
			   HWKM_BANK0_KM_CTL_CMD_ENABLE,
			   HWKM_BANK0_KM_CTL_CMD_ENABLE_SHIFT, 1);

	/* Confirm the FIFO clear bit has deasserted. */
	if (hwkm_reg_get_field(base, HWKM_BANK0_KM_CTL,
			       HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR,
			       HWKM_BANK0_KM_CTL_CMD_FIFO_CLEAR_SHIFT))
		return HWKM_ERR_FIFO_NOT_EMPTY;

	/* Push the command packet one word at a time. */
	for (i = 0; i < cmd_words; i++) {
		rc = hwkm_fifo_wait(base, HWKM_BANK0_KM_STATUS,
				    HWKM_BANK0_KM_STATUS_CMD_FIFO_AVAIL_SPACE,
				    HWKM_BANK0_KM_STATUS_CMD_FIFO_AVAIL_SPACE_SHIFT);
		if (rc)
			return rc;

		HWKM_REG_WRITE(base, HWKM_BANK0_KM_CMD_FIFO, cmd[i]);
	}

	/* Pull the response packet one word at a time. */
	for (i = 0; i < rsp_words; i++) {
		rc = hwkm_fifo_wait(base, HWKM_BANK0_KM_STATUS,
				    HWKM_BANK0_KM_STATUS_RSP_FIFO_AVAIL_DATA,
				    HWKM_BANK0_KM_STATUS_RSP_FIFO_AVAIL_DATA_SHIFT);
		if (rc)
			return rc;

		rsp[i] = HWKM_REG_READ(base, HWKM_BANK0_KM_RSP_FIFO);
	}

	/* The hardware must report completion after the response is read. */
	if (!hwkm_reg_get_field(base, HWKM_BANK0_KM_IRQ_STATUS,
				HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE,
				HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE_SHIFT))
		return HWKM_ERR_RSP_OVERFLOW;

	/* Acknowledge completion. */
	HWKM_REG_WRITE(base, HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_CMD_DONE);

	return HWKM_SUCCESS;
}

/**
 * run_transaction() - Dispatch a packed command to the target hardware engine.
 * @t: Transaction whose @hdl->dest selects the engine.
 * @cmd: Packed command words.
 * @cmd_words: Number of words in @cmd.
 * @rsp: Buffer to receive response words.
 * @rsp_words: Capacity of @rsp in words.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
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

/**
 * hwkm_nist_keygen_handle() - Execute HWKM_OP_NIST_KEYGEN.
 * @t: Transaction carrying the keygen request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Key policy.
 *   CMD[3] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_nist_keygen_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_NIST_KEYGEN_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_NIST_KEYGEN_RSP_WORDS] = { };
	struct hwkm_hw_key_policy policy = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_NIST_KEYGEN,
		.slot1_desc = t->cmd.keygen.dks,
		.len = ARRAY_SIZE(cmd),
	};

	hwkm_pack_key_policy(&policy, &t->cmd.keygen.policy);
	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));
	/* CMD[1:2]: */
	memcpy(&cmd[HWKM_OPERATION_INFO_WORDS], &policy, sizeof(policy));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_NIST_KEYGEN_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

/**
 * hwkm_system_kdf_handle() - Execute HWKM_OP_SYSTEM_KDF.
 * @t: Transaction carrying the KDF request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Child key policy.
 *   CMD[3] = BSVE[0] if bsve is enabled, 0 otherwise.
 *   CMD[4:5] = BSVE[1:2] only if bsve is enabled.
 *   CMD[n:] = Software context, padded to 32-bit words.
 *   CMD[last] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_system_kdf_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_SYSTEM_KDF_CMD_WORDS +
		     HWKM_BSVE_WORDS + HWKM_SOFTWARE_CONTEXT_WORDS] = { };
	uint32_t rsp[HWKM_OP_SYSTEM_KDF_RSP_WORDS] = { };
	struct hwkm_hw_key_policy policy = { };
	struct hwkm_operation_info op = { };
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

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_SYSTEM_KDF,
		.slot1_desc = t->cmd.kdf.dks,
		.slot2_desc = t->cmd.kdf.kdk,
		.op_flag = t->cmd.kdf.bsve.enabled ? 1U : 0U,
		.context_len = ctx_words,
		.len = ctx_idx + 1, /* incl. CRC, excl. context. */
	};

	hwkm_pack_key_policy(&policy, &t->cmd.kdf.policy);
	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));
	/* CMD[1:2]: */
	memcpy(&cmd[HWKM_OPERATION_INFO_WORDS], &policy, sizeof(policy));

	if (t->cmd.kdf.bsve.enabled) {
		struct hwkm_hw_kdf_bsve bsve = { };

		hwkm_pack_kdf_bsve(&bsve, &t->cmd.kdf.bsve, t->cmd.kdf.mks);
		/* CMD[3:5]: */
		memcpy(&cmd[HWKM_OPERATION_INFO_WORDS + HWKM_KEY_POLICY_WORDS],
		       &bsve, sizeof(bsve));
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

/**
 * hwkm_key_wrap_export_handle() - Execute HWKM_OP_KEY_WRAP_EXPORT.
 * @t: Transaction carrying the wrap-export request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1:3] = BSVE, or 0 if BSVE is disabled.
 *   CMD[4] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *   RSP[2:18] = Wrapped key blob on success.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_key_wrap_export_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_WRAP_EXPORT_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_WORDS] = { };
	struct hwkm_hw_wrapping_bsve bsve = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_KEY_WRAP_EXPORT,
		.slot1_desc = t->cmd.wrap.sks,
		.slot2_desc = t->cmd.wrap.kwk,
		.len = ARRAY_SIZE(cmd),
	};

	hwkm_pack_wrapping_bsve(&bsve, &t->cmd.wrap.bsve);
	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));
	/* CMD[1:3]: */
	memcpy(&cmd[HWKM_OPERATION_INFO_WORDS], &bsve, sizeof(bsve));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS) {
		t->rsp.status = rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_ERR_IDX];
		/* On operation success, RSP[2:18]: */
		if (!t->rsp.status) {
			memcpy(t->rsp.wrap.wkb,
			       &rsp[HWKM_OP_KEY_WRAP_EXPORT_RSP_WRAPPED_KEY_IDX],
			       HWKM_MAX_BLOB_SIZE);
		}
	}

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

/**
 * hwkm_key_unwrap_import_handle() - Execute HWKM_OP_KEY_UNWRAP_IMPORT.
 * @t: Transaction carrying the unwrap-import request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1:17] = Wrapped key blob.
 *   CMD[18] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_key_unwrap_import_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_UNWRAP_IMPORT_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_UNWRAP_IMPORT_RSP_WORDS] = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_KEY_UNWRAP_IMPORT,
		.slot1_desc = t->cmd.unwrap.dks,
		.slot2_desc = t->cmd.unwrap.kwk,
		.len = ARRAY_SIZE(cmd),
	};

	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));
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

/**
 * hwkm_key_slot_clear_handle() - Execute HWKM_OP_KEY_SLOT_CLEAR.
 * @t: Transaction carrying the clear request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_key_slot_clear_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_SLOT_CLEAR_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_SLOT_CLEAR_RSP_WORDS] = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_KEY_SLOT_CLEAR,
		.slot1_desc = t->cmd.clear.dks,
		.op_flag = t->cmd.clear.is_double_key ? 1U : 0U,
		.len = ARRAY_SIZE(cmd),
	};

	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_KEY_SLOT_CLEAR_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

/**
 * hwkm_key_slot_rdwr_handle() - Execute HWKM_OP_KEY_SLOT_RDWR.
 * @t: Transaction carrying the read/write request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1:2] = Written policy, or 0 for read.
 *   CMD[3:10] = Written key value, or 0 for read.
 *   CMD[11] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *   RSP[2:3] = Read policy, or 0 for write.
 *   RSP[4:11] = Read key value, or 0 for write.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_key_slot_rdwr_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_KEY_SLOT_RDWR_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_WORDS] = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_KEY_SLOT_RDWR,
		.slot1_desc = t->cmd.rdwr.slot,
		.op_flag = t->cmd.rdwr.is_write ? 1U : 0U,
		.len = ARRAY_SIZE(cmd),
	};

	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));

	if (t->cmd.rdwr.is_write) {
		struct hwkm_hw_key_policy policy = { };

		hwkm_pack_key_policy(&policy, &t->cmd.rdwr.policy);
		/* CMD[1:2]: */
		memcpy(&cmd[HWKM_OPERATION_INFO_WORDS], &policy,
		       sizeof(policy));
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
			struct hwkm_hw_key_policy policy = { };

			/* RSP[2:3]: */
			memcpy(&policy,
			       &rsp[HWKM_OP_KEY_SLOT_RDWR_RSP_POLICY_IDX],
			       sizeof(policy));
			hwkm_unpack_key_policy(&t->rsp.rdwr.policy, &policy);
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

/**
 * hwkm_set_tpkey_handle() - Execute HWKM_OP_SET_TPKEY.
 * @t: Transaction carrying the set-TPKEY request and response.
 *
 * Command format:
 *   CMD[0] = Operation info.
 *   CMD[1] = CRC word, left as 0 when CRC checking is disabled.
 *
 * Response format:
 *   RSP[0] = Unused.
 *   RSP[1] = Error status.
 *
 * Return: HWKM_SUCCESS on transport success, or a HWKM_ERR_* code.
 * Hardware command failure is reported in t->rsp.status.
 */
static int hwkm_set_tpkey_handle(struct hwkm_transaction *t)
{
	uint32_t cmd[HWKM_OP_SET_TPKEY_CMD_WORDS] = { };
	uint32_t rsp[HWKM_OP_SET_TPKEY_RSP_WORDS] = { };
	struct hwkm_operation_info op = { };
	int rc = HWKM_ERR_GENERIC;

	if (!t || !t->hdl)
		return HWKM_ERR_INVALID_ARG;

	if (t->hdl->dest != HWKM_KEY_DEST_KM_MASTER)
		return HWKM_ERR_INVALID_DEST;

	op = (struct hwkm_operation_info){
		.op = HWKM_OP_SET_TPKEY,
		.slot1_desc = t->cmd.set_tpkey.sks,
		.len = ARRAY_SIZE(cmd),
	};

	/* CMD[0]: */
	memcpy(&cmd[0], &op, sizeof(op));

	rc = run_transaction(t, cmd, ARRAY_SIZE(cmd), rsp, ARRAY_SIZE(rsp));
	/* On success, RSP[1]: */
	if (rc == HWKM_SUCCESS)
		t->rsp.status = rsp[HWKM_OP_SET_TPKEY_RSP_ERR_IDX];

	memzero_explicit(cmd, sizeof(cmd));
	memzero_explicit(rsp, sizeof(rsp));

	return rc;
}

/**
 * hwkm_transaction_dispatch() - Route a transaction to its opcode handler.
 * @t: Transaction to execute.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
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

/**
 * hwkm_handle_init() - Initialize an HWKM handle.
 * @hdl: Handle to initialize.
 * @dest: Target hardware engine.
 *
 * Initializes @hdl for queuing commands to @dest.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
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

/**
 * hwkm_enqueue() - Enqueue a transaction on a handle.
 * @hdl: Handle that owns the queue.
 * @t: Transaction to enqueue.
 *
 * Associates @t with @hdl and appends it to the tail of the queue.
 *
 * Return: HWKM_SUCCESS on success, or a HWKM_ERR_* code on failure.
 */
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

/**
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

/**
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
