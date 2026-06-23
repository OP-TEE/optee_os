// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <platform_config.h>

#include <initcall.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include <hwkm.h>
#include <hwkm_errno.h>
#include <hwkm_regs.h>

#include "clock_group_qcom.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, HWKM_MASTER_BASE, HWKM_MASTER_SIZE);

static_assert(HW_UNIQUE_KEY_LENGTH <= HWKM_MAX_KEY_SIZE);

/*
 * BANK0 BBAC bitmap for the slots managed by this driver.
 *
 * BBAC_0 covers slots 0..31. Slots not present in this bitmap remain
 * inaccessible from BANK0.
 */
#define HWKM_BBAC_BIT(_slot)	BIT((_slot) % 32)

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

static struct hwkm_drv_ctx g_hwkm_ctx = {
	.hwkm_lock = MUTEX_INITIALIZER,
};

/**
 * hwkm_get_context() - Return the driver context, or NULL if not initialized.
 */
struct hwkm_drv_ctx *hwkm_get_context(void)
{
	return g_hwkm_ctx.initialized ? &g_hwkm_ctx : NULL;
}

/**
 * hwkm_transaction_alloc() - Allocate and zero one HWKM transaction.
 *
 * Return: zero-initialized transaction on success, or NULL on failure.
 */
struct hwkm_transaction *hwkm_transaction_alloc(void)
{
	return calloc(1, sizeof(struct hwkm_transaction));
}

/**
 * hwkm_transaction_free() - Wipe and free one HWKM transaction.
 * @t: Transaction to release.
 */
void hwkm_transaction_free(struct hwkm_transaction *t)
{
	if (!t)
		return;

	memzero_explicit(t, sizeof(*t));
	free(t);
}

/**
 * hwkm_init() - Initialize the HWKM instance.
 *
 * Initialization sequence:
 *   1. Check the hardware self-test status.
 *   2. Disable packet CRC checking.
 *   3. Program BANK0 BBAC for the slots managed by this driver.
 *   4. Clear the documented spurious RSP_FIFO_FULL sticky bit.
 *   5. Publish the mapped base and mark the driver initialized.
 *
 * Return: TEE_SUCCESS on success, or a TEE_ERROR_* code on failure.
 */
static TEE_Result hwkm_init(void)
{
	uint32_t status = 0;
	vaddr_t base = 0;

	base = (vaddr_t)phys_to_virt(HWKM_MASTER_BASE, MEM_AREA_IO_SEC,
				     HWKM_MASTER_SIZE);
	if (!base)
		return TEE_ERROR_GENERIC;

	/* Check the hardware self-test status. */
	status = HWKM_REG_READ(base, HWKM_TZ_KM_STATUS);
	if (status & (HWKM_TZ_KM_STATUS_BIST_ERROR |
		      HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_ERROR)) {
		EMSG("hwkm: BIST failed, status=0x%08"PRIx32, status);
		return TEE_ERROR_GENERIC;
	}

	/* Disable CRC checking on command packets. */
	hwkm_reg_set_field(base, HWKM_TZ_KM_CTL,
			   HWKM_TZ_KM_CTL_CRC_CHECK_EN,
			   HWKM_TZ_KM_CTL_CRC_CHECK_EN_SHIFT, 0);

	HWKM_REG_WRITE(base, HWKM_BANK0_AC + HWKM_BANKn_AC_BBAC_0,
		       HWKM_BANK0_BBAC_0);
	HWKM_REG_WRITE(base, HWKM_BANK0_AC + HWKM_BANKn_AC_BBAC_1, 0);
	HWKM_REG_WRITE(base, HWKM_BANK0_AC + HWKM_BANKn_AC_BBAC_2, 0);
	HWKM_REG_WRITE(base, HWKM_BANK0_AC + HWKM_BANKn_AC_BBAC_3, 0);
	HWKM_REG_WRITE(base, HWKM_BANK0_AC + HWKM_BANKn_AC_BBAC_4, 0);

	/*
	 * Clear the spurious RSP_FIFO_FULL sticky bit.
	 * HW errata QCTDD06252768: RSP_FIFO_FULL may be set after reset even
	 * though the FIFO is empty. Write 1 to clear it unconditionally so
	 * it does not interfere with CMD_DONE polling in
	 * master_run_transaction().
	 */
	HWKM_REG_WRITE(base, HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL);

	g_hwkm_ctx.base = base;
	g_hwkm_ctx.initialized = true;

	return TEE_SUCCESS;
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

	res = tee_otp_get_hw_unique_key(&huk);
	if (res) {
		EMSG("hwkm: HUK derivation failed: 0x%08"PRIx32, res);
		panic("HWKM HUK derivation failure");
	}

	memzero_explicit(&huk, sizeof(huk));

	return TEE_SUCCESS;
}

driver_init(hwkm_driver_init);
