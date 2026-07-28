// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 */

#include <hwkm.h>
#include <hwkm_ice.h>
#include <hwkm_regs.h>
#include <io.h>
#include <kernel/delay.h>

#define HWKM_ICE_MAX_RETRIES	100000U

/*
 * HWKM_ICE_DEFAULT_TPKEY_SLOT - destination key slot used by the ICE slave
 * to receive the TPKEY.
 */
#define HWKM_ICE_DEFAULT_TPKEY_SLOT	0x92U

/*
 * ice_set_standard_mode() - Put the ICE HWKM instance into standard mode.
 * @base: MMIO base address of the ICE module.
 *
 * Programs the TZ control register to the standard-mode value expected by
 * the ICE init flow before status polling and access-control setup.
 */
static void ice_set_standard_mode(vaddr_t base)
{
	io_write32_off(base + HWKM_ICE_TZ_REGS_OFFSET, HWKM_TZ_KM_CTL, 0x7);
}

/*
 * ice_wait_init_done() - Poll a status bit until the ICE init step completes.
 * @base: MMIO base used for register access.
 * @reg: Register offset to poll.
 * @mask: Bit mask of the completion field.
 *
 * Uses bounded retries with udelay(10) to avoid indefinite waits during
 * bring-up sequencing.
 *
 * Return: HWKM_SUCCESS when the field clears, or HWKM_ERR_FIFO_TIMEOUT.
 */
static int ice_wait_init_done(vaddr_t base, uint32_t reg, uint32_t mask)
{
	uint32_t retries = 0;

	/* BIT set to 1 implies INIT done. */
	while (!io_read32_off_field(base, reg, mask)) {
		if (++retries > HWKM_ICE_MAX_RETRIES)
			return HWKM_ERR_FIFO_TIMEOUT;
		udelay(10);
	}

	return HWKM_SUCCESS;
}

/*
 * ice_wait_init() - Wait for all ICE bring-up completion status bits.
 * @base: MMIO base address of the ICE module.
 *
 * Waits for BIST, crypto-lib BIST, boot command list 0/1, and key-table clear
 * completion indicators before allowing command traffic.
 *
 * Return: HWKM_SUCCESS on success, or HWKM_ERR_FIFO_TIMEOUT.
 */
static int ice_wait_init(vaddr_t base)
{
	uint32_t done_bits[] = {
		HWKM_TZ_KM_STATUS_BIST_DONE,
		HWKM_TZ_KM_STATUS_CRYPTO_LIB_BIST_DONE,
		HWKM_TZ_KM_STATUS_BOOT_CMD_LIST0_DONE,
		HWKM_TZ_KM_STATUS_BOOT_CMD_LIST1_DONE,
		HWKM_TZ_KM_STATUS_KT_CLEAR_DONE,
	};
	size_t i = 0;
	int rc = HWKM_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(done_bits); i++) {
		rc = ice_wait_init_done(base + HWKM_ICE_TZ_REGS_OFFSET,
				       HWKM_TZ_KM_STATUS, done_bits[i]);
		if (rc)
			return rc;
	}

	return rc;
}

/*
 * ice_setup_finalize() - Finalize ICE HWKM register state after init done.
 * @base: MMIO base address of the ICE module.
 *
 * Disables CRC checking, grants TZ BANK0 key-slot access, and clears the
 * spurious RSP_FIFO_FULL sticky interrupt condition (QCTDD06252768).
 */
static void ice_setup_finalize(vaddr_t base)
{
	/* Disable CRC checking on command packets. */
	io_write32_off_field(base + HWKM_ICE_TZ_REGS_OFFSET, HWKM_TZ_KM_CTL,
			     HWKM_TZ_KM_CTL_CRC_CHECK_EN, 0x0);

	/* Grant TZ (BANK0) unrestricted access to all key slots. */
	io_write32_off(base + HWKM_ICE_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_0, 0xFFFFFFFF);
	io_write32_off(base + HWKM_ICE_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_1, 0xFFFFFFFF);
	io_write32_off(base + HWKM_ICE_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_2, 0xFFFFFFFF);
	io_write32_off(base + HWKM_ICE_BANK0_AC_REGS_OFFSET,
		       HWKM_BANKn_AC_BBAC_3, 0xFFFFFFFF);
	io_write32_off(base + HWKM_ICE_BANK0_AC_REGS_OFFSET,
                       HWKM_BANKn_AC_BBAC_4, 0xFFFFFFFF);

	/* Clear spurious RSP_FIFO_FULL sticky bit (HW errata QCTDD06252768). */
	io_write32_off(base + HWKM_ICE_BANK0_REGS_OFFSET,
		       HWKM_BANK0_KM_IRQ_STATUS,
		       HWKM_BANK0_KM_IRQ_STATUS_RSP_FIFO_FULL);
}

/*
 * ice_init() - Execute the ICE one-time HWKM initialization sequence.
 * @base: MMIO base address of the ICE module.
 *
 * Transitions to standard mode, waits for init completion status bits, then
 * applies post-init register configuration required for transactions.
 *
 * Return: HWKM_SUCCESS on success, or an HWKM_ERR_* code on failure.
 */
static int ice_init(vaddr_t base)
{
	int rc = HWKM_SUCCESS;

	ice_set_standard_mode(base);
	rc = ice_wait_init(base);
	if (rc)
		/*
		 * If HWKM is supported and an ICE HWKM transaction was
		 * requested, ICE should remain in standard mode even in case
		 * of failure.
		 */
		return rc;

	ice_setup_finalize(base);

	return rc;
}

/*
 * is_ice_in_standard_mode() - Check whether ICE HWKM is in standard mode.
 * @base: MMIO base address of the ICE module.
 *
 * Reads TZ_KM_CTL and validates that the mode value matches the expected
 * standard-mode configuration.
 *
 * Return: true if standard mode is active, false otherwise.
 */
static bool is_ice_in_standard_mode(vaddr_t base)
{
	uint32_t mode = io_read32_off_field(base + HWKM_ICE_TZ_REGS_OFFSET,
					    HWKM_TZ_KM_CTL,
					    HWKM_TZ_KM_CTL_ICE_LEGACY_MODE_EN_OTP);

	/* Standard mode */
	if (mode == 0x0)
		return true;

	return false;
}

/*
 * hwkm_ice_enable_tpkey_receive() - Arm ICE to receive an incoming TPKEY.
 * @base: MMIO base address of the ICE module.
 *
 * Clears EN, programs TPKEY_DKS to the ICE default TPKEY slot, and re-enables
 * EN to open the receive window before issuing SET_TPKEY on KM_MASTER.
 */
static void hwkm_ice_enable_tpkey_receive(vaddr_t base)
{
	vaddr_t tz_base = base + HWKM_ICE_TZ_REGS_OFFSET;

	/* Deassert EN first to reset any stale receive state. */
	io_write32_off_field(tz_base, HWKM_TZ_TPKEY_RECEIVE_CTL,
			     HWKM_TZ_TPKEY_RECEIVE_CTL_EN, 0);

	/* Open the receive window. */
	io_write32_off_field(tz_base, HWKM_TZ_TPKEY_RECEIVE_CTL,
			     HWKM_TZ_TPKEY_RECEIVE_CTL_EN, 1);

	/* Program the destination key slot. */
	io_write32_off_field(tz_base, HWKM_TZ_TPKEY_RECEIVE_CTL,
			     HWKM_TZ_TPKEY_RECEIVE_CTL_TPKEY_DKS,
			     HWKM_ICE_DEFAULT_TPKEY_SLOT);
}

/*
 * ice_wait_tpkey_done() - Poll until ICE reports TPKEY receive completion.
 * @base: MMIO base address of the ICE module.
 *
 * Waits for TZ_TPKEY_RECEIVE_STATUS.DONE with bounded retries to ensure TPKEY
 * handoff completion is observed before disarming receive.
 *
 * Return: HWKM_SUCCESS when DONE is set, or HWKM_ERR_FIFO_TIMEOUT.
 */
static int ice_wait_tpkey_done(vaddr_t base)
{
	uint32_t retries = 0;
	vaddr_t tz_base = base + HWKM_ICE_TZ_REGS_OFFSET;

	while (!io_read32_off_field(tz_base, HWKM_TZ_TPKEY_RECEIVE_STATUS,
				    HWKM_TZ_TPKEY_RECEIVE_STATUS_DONE)) {
		if (++retries > HWKM_ICE_MAX_RETRIES)
			return HWKM_ERR_FIFO_TIMEOUT;
		udelay(10);
	}

	return HWKM_SUCCESS;
}

/*
 * hwkm_ice_disable_tpkey_receive() - Disarm ICE TPKEY receive after completion.
 * @base: MMIO base address of the ICE module.
 *
 * Waits for DONE and then clears TPKEY_RECEIVE_CTL.EN to close the receive
 * window and avoid stale state across transactions.
 *
 * Return: HWKM_SUCCESS on success, or HWKM_ERR_FIFO_TIMEOUT.
 */
static int hwkm_ice_disable_tpkey_receive(vaddr_t base)
{
	int rc = ice_wait_tpkey_done(base);
	io_write32_off_field(base + HWKM_ICE_TZ_REGS_OFFSET,
			     HWKM_TZ_TPKEY_RECEIVE_CTL,
			     HWKM_TZ_TPKEY_RECEIVE_CTL_EN, 0);

	return rc;
}

/*
 * is_hwkm_ice_tpkey_set() - Check whether ICE already has a TPKEY installed.
 * @base: MMIO base address of the ICE module.
 *
 * Uses TZ_TPKEY_RECEIVE_STATUS.DONE as the persisted hardware indicator that a
 * prior SET_TPKEY transfer completed successfully.
 *
 * Return: true when TPKEY is present, false otherwise.
 */
static bool is_hwkm_ice_tpkey_set(vaddr_t base)
{
	return io_read32_off_field(base + HWKM_ICE_TZ_REGS_OFFSET,
				   HWKM_TZ_TPKEY_RECEIVE_STATUS,
				   HWKM_TZ_TPKEY_RECEIVE_STATUS_DONE) == 1U;
}

/*
 * hwkm_ice_set_tpkey() - Push TPKEY from KM_MASTER to the ICE slave.
 * @base: MMIO base address of the ICE module.
 *
 * Arms ICE TPKEY receive, issues SET_TPKEY on KM_MASTER using
 * HWKM_SLOT_TPKEY_SLOT, then waits for DONE and disarms receive.
 *
 * Return: HWKM_SUCCESS on success, or an HWKM_ERR_* code on failure.
 */
static int hwkm_ice_set_tpkey(vaddr_t base)
{
	struct hwkm_transaction t = {
		.cmd = {
			.op = HWKM_OP_SET_TPKEY,
			.set_tpkey = { .sks = HWKM_SLOT_TPKEY_SLOT },
		},
	};
	int rc = HWKM_ERR_GENERIC;

	/* Step 1: Arm the ICE slave to receive the incoming TPKEY. */
	hwkm_ice_enable_tpkey_receive(base);

	/* Step 2: Issue SET_TPKEY on the master -- this pushes the key to the slave. */
	rc = hwkm_run_transaction(HWKM_KEY_DEST_KM_MASTER, &t);
	if (rc)
		goto out;

	if (t.rsp.status) {
		rc = HWKM_ERR_GENERIC;
		goto out;
	}

out:
	/* Step 3: Wait for DONE and disarm regardless of SET_TPKEY outcome. */
	if (hwkm_ice_disable_tpkey_receive(base) && !rc)
		rc = HWKM_ERR_FIFO_TIMEOUT;

	return rc;
}

/*
 * hwkm_ice_configure() - Ensure ICE HWKM is ready and TPKEY is installed.
 * @base: MMIO base address of the ICE module.
 *
 * Runs ICE init if not already in standard mode. If TPKEY is not yet set,
 * performs the TPKEY handoff sequence before allowing ICE transactions.
 *
 * Return: HWKM_SUCCESS on success, or an HWKM_ERR_* code on failure.
 */
int hwkm_ice_configure(vaddr_t base)
{
	int rc;

	if (!is_ice_in_standard_mode(base)) {
		rc = ice_init(base);
		if (rc)
			return rc;
	}

	if (is_hwkm_ice_tpkey_set(base))
		return HWKM_SUCCESS;

	return hwkm_ice_set_tpkey(base);
}
