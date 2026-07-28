// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <hwkm.h>
#include <hwkm_errno.h>
#include <hwkm_regs.h>
#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib_ext.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, HWKM_MASTER_BASE, HWKM_MASTER_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, HWKM_CRYPTO0_BASE, HWKM_CRYPTO0_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, HWKM_ICE_BASE, HWKM_ICE_SIZE);

static_assert(HW_UNIQUE_KEY_LENGTH <= HWKM_MAX_KEY_SIZE);

#define HWKM_BBAC_BIT(slot) BIT((slot) % 32)

#define HWKM_BANK0_BBAC_0 \
	(HWKM_BBAC_BIT(HWKM_SLOT_TZ_NKDK_L2)                 | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_PKDK_L2)                 | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_SKDK_L2)                 | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_UKDK_L2)                 | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TPKEY_SLOT)                 | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TPKEY_ODD_SLOT)             | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_SWAP_KEY_SLOT)           | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_SWAP_KEY_ODD_SLOT)       | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_WRAP_KEY_SLOT)           | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_WRAP_KEY_ODD_SLOT)       | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1)   | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT2)   | \
	 HWKM_BBAC_BIT(HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR1)     | \
	 HWKM_BBAC_BIT(HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR1_ODD) | \
	 HWKM_BBAC_BIT(HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR2)     | \
	 HWKM_BBAC_BIT(HWKM_SLOT_PERSISTENT_SHARED_SLOT_PAIR2_ODD) | \
	 HWKM_BBAC_BIT(HWKM_SLOT_TZ_MIXING_KEY_SLOT))

static struct hwkm_drv_ctx hwkm_ctx = {
	.hwkm_lock = MUTEX_INITIALIZER,
};

struct hwkm_drv_ctx *hwkm_get_context(void)
{
	return hwkm_ctx.initialized ? &hwkm_ctx : NULL;
}

struct hwkm_transaction *hwkm_transaction_alloc(void)
{
	return calloc(1, sizeof(struct hwkm_transaction));
}

void hwkm_transaction_free(struct hwkm_transaction *t)
{
	free_wipe(t);
}

#define HWKM_ERR_ENTRY(m) { .status = (m), .name = #m }

static const struct { uint32_t status; const char *name; } hwkm_err_table[] = {
	/* Common errors. */
	HWKM_ERR_ENTRY(HWKM_ERR_RSP_FIFO_UNDERFLOW),
	HWKM_ERR_ENTRY(HWKM_ERR_CMD_FIFO_OVERFLOW),
	HWKM_ERR_ENTRY(HWKM_ERR_OPCODE_UNSUPPORTED),
	HWKM_ERR_ENTRY(HWKM_ERR_INVALID_OPCODE),
	HWKM_ERR_ENTRY(HWKM_ERR_INCORRECT_CMD_LENGTH),
	HWKM_ERR_ENTRY(HWKM_ERR_CRC_CHECK),
	HWKM_ERR_ENTRY(HWKM_ERR_BBAC_ACCESS),
	/* NIST_KEYGEN errors. */
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_KEYSLOT_ID_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_UNSUPPORTED_KEY_SIZE),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_KEY_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_TPKEY_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_KSK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_KWK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_KDF_DEPTH),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_INVALID_SECURITY_LEVEL),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_DKS_SLOT_NOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_NIST_KEYGEN_ERR_ACCESS_VIOLATION),
	/* KEY_SLOT_RDWR errors. */
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_KEYSLOT_ID_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_UNSUPPORTED_KEY_SIZE),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_SECURITY_LEVEL),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_KEY_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_TPKEY_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_KSK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_KWK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_INVALID_KDF_DEPTH),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_SECURITY_LEVEL_VIOLATION),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_SKS_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_DKS_SLOT_NOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_KEY_SLOT_RDWR_ERR_ACCESS_VIOLATION),
	/* SYSTEM_KDF errors. */
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_FR_RD_ERR_ON_SLAVE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_MKS_L1L2_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_SEC_CTRL_ACCESS),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_BSVE_BIT_NOT_SUPPORTED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_INVALID_SECURITY_LEVEL),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_INVALID_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_INVALID_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_SWAP_EXPORT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KEYPOLICY_CONSISTENCY),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_ENCRYPT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_UNEXPECTED_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_UNEXPECTED_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KDF_DEPTH_ERROR),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KDK_TYPE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KEY_SIZE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KEYSLOT_SLOT),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_KEYSLOT_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_DOUBLE_KEY_SLOT_NOT_EVEN),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_ACCESS_VIOLATION),
	HWKM_ERR_ENTRY(HWKM_SYSTEM_KDF_ERR_SECURITY_LEVEL_VIOLATION),
	/* KEY_WRAP_EXPORT errors. */
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KWK_DOUBLE_KEY_ODD_SLOT),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_ENCRYPT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SKS_SIZE_ERROR),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SKS_SLOT_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KWK_SIZE_ERROR),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KWK_SLOT_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_WRAP_WITH_TPKEY_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SWAP_EXPORT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_WRAP_EXPORT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_UNEXPECTED_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SECURITY_LEVEL_ERROR),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_UNEXPECTED_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KWK_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SKS_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_SKS_ACCESS_VIOLATION),
	HWKM_ERR_ENTRY(HWKM_EXPORT_ERR_KWK_ACCESS_VIOLATION),
	/* KEY_UNWRAP_IMPORT errors. */
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_UNWRAP_FAILED),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KWK_DOUBLE_KEY_ODD_SLOT),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KWK_SIZE_ERROR),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_DKS_SIZE_ERROR),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_DKS_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KWK_SLOT_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_SECURITY_LEVEL_ERROR),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_SECURITY_LEVEL),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_CONSISTENCY_CHECK_FAILED),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_TPKEY_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_KSK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_KWK_ATTRIB),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_INVALID_KDF_DEPTH),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_DECRYPT_NOT_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_UNEXPECTED_ALG_ALLOWED),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_UNEXPECTED_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KWK_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_DKS_SLOT_NOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_DKS_ACCESS_VIOLATION),
	HWKM_ERR_ENTRY(HWKM_IMPORT_ERR_KWK_ACCESS_VIOLATION),
	/* KEY_SLOT_CLEAR errors. */
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_KEYSLOT_ID_NOT_ACCESSIBLE),
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_KEYSLOT_ID_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_KEY_SIZE),
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_DOUBLE_KEY_DKS_SLOT_NOT_EVEN),
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_DKS_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_CLEAR_ERR_ACCESS_VIOLATION),
	/* SET_TPKEY errors. */
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_KT_PARITY),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_DOUBLE_KEY_SLOT_NOT_EVEN),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_WRONG_KEY_SIZE),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_KEYSLOT_ID_OUT_OF_RANGE),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_UNEXPECTED_KEY_TYPE),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_SKS_SLOT_EMPTY),
	HWKM_ERR_ENTRY(HWKM_TPKEY_ERR_ACCESS_VIOLATION),
};

const char *hwkm_err2str(uint32_t status)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(hwkm_err_table); i++)
		if (hwkm_err_table[i].status == status)
			return hwkm_err_table[i].name;

	return "Unknown";
}

static TEE_Result hwkm_init(void)
{
	uint32_t status = 0;
	vaddr_t base = 0;

	base = (vaddr_t)phys_to_virt(HWKM_MASTER_BASE, MEM_AREA_IO_SEC,
				     HWKM_MASTER_SIZE);
	if (!base)
		return TEE_ERROR_GENERIC;

	/* Check the hardware self-test status. */
	status = io_read32_off(base + HWKM_MASTER_TZ_REGS_OFFSET,
			       HWKM_TZ_KM_STATUS);
	if (status & (HWKM_TZ_KM_STATUS_BIST_ERROR |
		      HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR)) {
		EMSG("hwkm: BIST failed, status=0x%08"PRIx32, status);
		return TEE_ERROR_GENERIC;
	}

	/* Disable CRC checking on command packets. */
	io_write32_off_field(base + HWKM_MASTER_TZ_REGS_OFFSET, HWKM_TZ_KM_CTL,
			     HWKM_TZ_KM_CTL_CRC_CHECK_EN, 0);

	io_write32_off(base + HWKM_MASTER_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_0, HWKM_BANK0_BBAC_0);
	io_write32_off(base + HWKM_MASTER_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_1, 0);
	io_write32_off(base + HWKM_MASTER_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_2, 0);
	io_write32_off(base + HWKM_MASTER_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_3, 0);
	io_write32_off(base + HWKM_MASTER_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_4, 0);

	/*
	 * Clear the spurious RSP_FIFO_FULL sticky bit.
	 * HW errata QCTDD06252768: RSP_FIFO_FULL may be set after reset even
	 * though the FIFO is empty. Write 1 to clear it unconditionally so
	 * it does not interfere with CMD_DONE polling in
	 * master_run_transaction().
	 */
	io_write32_off(base + HWKM_MASTER_BANK0_REGS_OFFSET,
		       HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL);

	hwkm_ctx.base = base;
	hwkm_ctx.initialized = true;

	return TEE_SUCCESS;
}

static TEE_Result gpce_init(void)
{
	uint32_t status = 0;
	vaddr_t base = 0;

	base = (vaddr_t)phys_to_virt(HWKM_CRYPTO0_BASE, MEM_AREA_IO_SEC,
				     HWKM_CRYPTO0_SIZE);
	if (!base)
		return TEE_ERROR_GENERIC;

	/* Check the hardware self-test status. */
	status = io_read32_off(base + HWKM_CRYPTO0_TZ_REGS_OFFSET,
			       HWKM_TZ_KM_STATUS);
	if (status & (HWKM_TZ_KM_STATUS_BIST_ERROR |
		      HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR)) {
		EMSG("hwkm: gpce BIST failed, status=0x%08"PRIx32, status);
		return TEE_ERROR_GENERIC;
	}

	/* Disable CRC checking on command packets. */
	io_write32_off_field(base + HWKM_CRYPTO0_TZ_REGS_OFFSET, HWKM_TZ_KM_CTL,
			     HWKM_TZ_KM_CTL_CRC_CHECK_EN, 0);

	/* Grant TZ (BANK0) unrestricted access to all key slots. */
	io_write32_off(base + HWKM_CRYPTO0_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_0, 0xFFFFFFFF);
	io_write32_off(base + HWKM_CRYPTO0_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_1, 0xFFFFFFFF);
	io_write32_off(base + HWKM_CRYPTO0_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_2, 0xFFFFFFFF);
	io_write32_off(base + HWKM_CRYPTO0_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_3, 0xFFFFFFFF);

	/* Clear spurious RSP_FIFO_FULL sticky bit (HW errata QCTDD06252768). */
	io_write32_off(base + HWKM_CRYPTO0_BANK0_REGS_OFFSET,
		       HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL);

	hwkm_ctx.crypto0_base = base;

	return TEE_SUCCESS;
}

static TEE_Result hwkm_generate_tp_and_swap_keys(void)
{
	const struct hwkm_key_policy base_kdk_policy = {
		.km_by_tz_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_CMAC,
		.enc_allowed = true,
		.key_type = HWKM_KEY_TYPE_KDK,
		.kdf_depth = 1,
		.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	const struct hwkm_key_policy tpkey_policy = {
		.km_by_tz_allowed = true,
		.km_by_nsec_allowed = true,
		.km_by_modem_allowed = true,
		.km_by_spu_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_SIV,
		.enc_allowed = true,
		.dec_allowed = true,
		.key_type = HWKM_KEY_TYPE_TPKEY,
		.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	const struct hwkm_key_policy swap_key_policy = {
		.km_by_tz_allowed = true,
		.alg_allowed = HWKM_ALGO_AES256_SIV,
		.enc_allowed = true,
		.dec_allowed = true,
		.key_type = HWKM_KEY_TYPE_KSK,
		.security_lvl = HWKM_KEY_SECURITY_LVL_HW_KEY,
		.hw_destination = HWKM_KEY_DEST_KM_MASTER,
	};
	const struct hwkm_bsve bsve = {
		.enabled = true,
		.km_swc_en = true,
	};
	struct hwkm_transaction t_keygen = {
		.cmd = {
			.op = HWKM_OP_NIST_KEYGEN,
			.keygen = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.policy = base_kdk_policy,
			},
		},
	};
	struct hwkm_transaction t_tpkey_kdf = {
		.cmd = {
			.op = HWKM_OP_SYSTEM_KDF,
			.kdf = {
				.dks = HWKM_SLOT_TPKEY_SLOT,
				.kdk = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.policy = tpkey_policy,
				.bsve = bsve,
				.ctx_len = 16,
				.ctx = {
					0x54, 0x52, 0x41, 0x4e,
					0x53, 0x50, 0x4f, 0x52,
					0x54, 0x20, 0x4b, 0x45,
					0x59, 0x00, 0x00, 0x00,
				},
			},
		},
	};
	struct hwkm_transaction t_swap_kdf = {
		.cmd = {
			.op = HWKM_OP_SYSTEM_KDF,
			.kdf = {
				.dks = HWKM_SLOT_TZ_SWAP_KEY_SLOT,
				.kdk = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.policy = swap_key_policy,
				.bsve = bsve,
				.ctx_len = 8,
				.ctx = {
					0x53, 0x57, 0x41, 0x50,
					0x20, 0x4b, 0x45, 0x59,
				},
			},
		},
	};
	struct hwkm_transaction t_clear = {
		.cmd = {
			.op = HWKM_OP_KEY_SLOT_CLEAR,
			.clear = {
				.dks = HWKM_SLOT_TZ_GENERAL_PURPOSE_SLOT1,
				.is_double_key = false,
			},
		},
	};
	TEE_Result res = TEE_ERROR_GENERIC;
	int rc = HWKM_ERR_GENERIC;
	struct hwkm_drv_ctx *drv = hwkm_get_context();
	if (!drv)
		return TEE_ERROR_NOT_SUPPORTED;

	mutex_lock(&drv->hwkm_lock);
	rc = hwkm_run_transactions(HWKM_KEY_DEST_KM_MASTER, 4,
				   (struct hwkm_transaction *const[]){
					&t_keygen, &t_tpkey_kdf,
					&t_swap_kdf, &t_clear });
	if (rc) {
		res = hwkm_to_optee(rc);
		goto out_clear;
	}

	if (t_keygen.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: initial NIST_KEYGEN failed: %s",
		     hwkm_err2str(t_keygen.rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (t_tpkey_kdf.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: initial TPKEY SYSTEM_KDF failed: %s",
		     hwkm_err2str(t_tpkey_kdf.rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (t_swap_kdf.rsp.status != HWKM_RSP_ERR_SUCCESS) {
		EMSG("hwkm: initial SWAP SYSTEM_KDF failed: %s",
		     hwkm_err2str(t_swap_kdf.rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (t_clear.rsp.status != HWKM_RSP_ERR_SUCCESS &&
	    t_clear.rsp.status != HWKM_CLEAR_ERR_DKS_SLOT_EMPTY) {
		EMSG("hwkm: initial KEY_SLOT_CLEAR failed: %s",
		     hwkm_err2str(t_clear.rsp.status));
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	res = TEE_SUCCESS;
out_clear:
	/*
	 * If any of the above transactions fail, make an attempt
	 * to clear the TZ_GENERAL_PURPOSE_SLOT1 since it may have
	 * been left with the key material.
	 */
	hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t_clear);
out:
	mutex_unlock(&drv->hwkm_lock);
	return res;
}

static TEE_Result hwkm_driver_init(void)
{
	struct tee_hw_unique_key huk = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	res = hwkm_init();
	if (res) {
		EMSG("hwkm: init failed: 0x%08"PRIx32, res);
		return res;
	}

	res = gpce_init();
	if (res) {
		EMSG("hwkm: gpce init failed: 0x%08"PRIx32, res);
		return res;
	}

	res = hwkm_generate_tp_and_swap_keys();
	if (res) {
		EMSG("hwkm: TP and SWAP key generation failed: 0x%08"PRIx32, res);
		return res;
	}

	res = tee_otp_get_hw_unique_key(&huk);
	if (res) {
		EMSG("hwkm: HUK derivation failed: 0x%08"PRIx32, res);
		panic("HWKM HUK derivation failure");
	}

	memzero_explicit(&huk, sizeof(huk));

	return TEE_SUCCESS;
}

service_init(hwkm_driver_init);
