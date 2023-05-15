// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings Hardware Abstration Layer.
 *          Implementation of primitives to access HW
 */
#include <caam_common.h>
#include <caam_hal_jr.h>
#include <caam_io.h>
#include <caam_pwr.h>
#include <caam_utils_delay.h>
#include <registers/ctrl_regs.h>
#include <registers/jr_regs.h>

#ifdef CFG_NXP_CAAM_RUNTIME_JR
/*
 * List of common JR registers to save/restore
 */
static const struct reglist jr_backup[] = {
	BACKUP_REG(JRX_IRBAR, 2, 0, 0),
	BACKUP_REG(JRX_IRSR, 1, 0, 0),
	BACKUP_REG(JRX_ORBAR, 2, 0, 0),
	BACKUP_REG(JRX_ORSR, 1, 0, 0),
	BACKUP_REG(JRX_JRCFGR_LS, 1, 0, 0),
};
#endif /* CFG_NXP_CAAM_RUNTIME_JR */

enum caam_status caam_hal_jr_reset(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t reg_val = 0;

	/*
	 * Reset is done in 2 steps:
	 *  - Flush all pending jobs (Set RESET bit)
	 *  - Reset the Job Ring (Set RESET bit second time)
	 */

	/* Mask interrupts to poll for reset completion status */
	io_setbits32(baseaddr + JRX_JRCFGR_LS, JRX_JRCFGR_LS_IMSK);

	/* Initiate flush (required prior to reset) */
	io_caam_write32(baseaddr + JRX_JRCR, JRX_JRCR_RESET);

	do {
		caam_udelay(100);
		reg_val = io_caam_read32(baseaddr + JRX_JRINTR);
		reg_val &= BM_JRX_JRINTR_HALT;
	} while ((reg_val == JRINTR_HALT_ONGOING) && --timeout);

	if (!timeout || reg_val != JRINTR_HALT_DONE) {
		EMSG("Failed to flush job ring\n");
		return CAAM_FAILURE;
	}

	/* Initiate reset */
	timeout = 100;
	io_caam_write32(baseaddr + JRX_JRCR, JRX_JRCR_RESET);
	do {
		caam_udelay(100);
		reg_val = io_caam_read32(baseaddr + JRX_JRCR);
	} while ((reg_val & JRX_JRCR_RESET) && --timeout);

	if (!timeout) {
		EMSG("Failed to reset job ring\n");
		return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

void caam_hal_jr_config(vaddr_t baseaddr, uint8_t nbjobs, uint64_t inrings,
			uint64_t outrings)
{
	uint32_t value = 0;

	/* Setup the JR input queue */
#if defined(CFG_CAAM_64BIT) && defined(CFG_CAAM_LITTLE_ENDIAN)
	io_caam_write32(baseaddr + JRX_IRBAR, inrings);
	io_caam_write32(baseaddr + JRX_IRBAR + 4, inrings >> 32);
#else
	io_caam_write32(baseaddr + JRX_IRBAR, inrings >> 32);
	io_caam_write32(baseaddr + JRX_IRBAR + 4, inrings);
#endif
	io_caam_write32(baseaddr + JRX_IRSR, nbjobs);

	/* Setup the JR output queue */
#if defined(CFG_CAAM_64BIT) && defined(CFG_CAAM_LITTLE_ENDIAN)
	io_caam_write32(baseaddr + JRX_ORBAR, outrings);
	io_caam_write32(baseaddr + JRX_ORBAR + 4, outrings >> 32);
#else
	io_caam_write32(baseaddr + JRX_ORBAR, outrings >> 32);
	io_caam_write32(baseaddr + JRX_ORBAR + 4, outrings);
#endif
	io_caam_write32(baseaddr + JRX_ORSR, nbjobs);

	/* Disable the JR interrupt */
	caam_hal_jr_disable_itr(baseaddr);

	/*
	 * Configure interrupt and disable it:
	 * Optimization to generate an interrupt either when there are
	 *   half of the job done
	 *   or when there is a job done and 10 clock cycles elapsed without
	 *      new job completion
	 */
	value = JRX_JRCFGR_LS_ICTT(10);
	value |= JRX_JRCFGR_LS_ICDCT(nbjobs / 2);
	value |= JRX_JRCFGR_LS_ICEN;
	value |= JRX_JRCFGR_LS_IMSK;
	io_caam_write32(baseaddr + JRX_JRCFGR_LS, value);

#ifdef CFG_NXP_CAAM_RUNTIME_JR
	caam_pwr_add_backup(baseaddr, jr_backup, ARRAY_SIZE(jr_backup));
#endif
}

uint32_t caam_hal_jr_read_nbslot_available(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRX_IRSAR);
}

void caam_hal_jr_add_newjob(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRX_IRJAR, 1);
}

uint32_t caam_hal_jr_get_nbjob_done(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRX_ORSFR);
}

void caam_hal_jr_del_job(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRX_ORJRR, 1);
}

#ifdef CFG_CAAM_ITR
void caam_hal_jr_disable_itr(vaddr_t baseaddr)
{
	io_setbits32(baseaddr + JRX_JRCFGR_LS, JRX_JRCFGR_LS_IMSK);
	io_setbits32(baseaddr + JRX_JRINTR, JRX_JRINTR_JRI);
}

void caam_hal_jr_enable_itr(vaddr_t baseaddr)
{
	io_mask32(baseaddr + JRX_JRCFGR_LS, ~JRX_JRCFGR_LS_IMSK,
		  JRX_JRCFGR_LS_IMSK);
}
#else
void caam_hal_jr_disable_itr(vaddr_t baseaddr __unused) {}
void caam_hal_jr_enable_itr(vaddr_t baseaddr __unused) {}
#endif /* CFG_CAAM_ITR */

bool caam_hal_jr_check_ack_itr(vaddr_t baseaddr)
{
	uint32_t val = 0;

	val = io_caam_read32(baseaddr + JRX_JRINTR);

	if ((val & JRX_JRINTR_JRI) == JRX_JRINTR_JRI) {
		/* Acknowledge interrupt */
		io_setbits32(baseaddr + JRX_JRINTR, JRX_JRINTR_JRI);
		return true;
	}

	return false;
}

enum caam_status caam_hal_jr_halt(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val = 0;

	/* Mask interrupts to poll for completion status */
	io_setbits32(baseaddr + JRX_JRCFGR_LS, JRX_JRCFGR_LS_IMSK);

	/* Request Job ring halt */
	io_caam_write32(baseaddr + JRX_JRCR, JRX_JRCR_PARK);

	/* Check if there is a job running */
	val = io_caam_read32(baseaddr + JRX_IRSR);
	if ((caam_hal_jr_read_nbslot_available(baseaddr) == val) &&
	    (io_caam_read32(baseaddr + JRX_CSTA) != JRX_CSTA_BSY))
		return CAAM_NO_ERROR;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = io_caam_read32(baseaddr + JRX_JRINTR);
		val &= BM_JRX_JRINTR_HALT;
	} while ((val != JRINTR_HALT_DONE) && --timeout);

	if (!timeout)
		return CAAM_BUSY;

	return CAAM_NO_ERROR;
}

enum caam_status caam_hal_jr_flush(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val = 0;

	/* Mask interrupts to poll for completion status */
	io_setbits32(baseaddr + JRX_JRCFGR_LS, JRX_JRCFGR_LS_IMSK);

	/* Request Job ring to flush input queue */
	io_caam_write32(baseaddr + JRX_JRCR, JRX_JRCR_RESET);

	/* Check if there is a job running */
	val = io_caam_read32(baseaddr + JRX_IRSR);
	if ((caam_hal_jr_read_nbslot_available(baseaddr) == val) &&
	    (io_caam_read32(baseaddr + JRX_CSTA) != JRX_CSTA_BSY))
		return CAAM_NO_ERROR;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = io_caam_read32(baseaddr + JRX_JRINTR);
		val &= BM_JRX_JRINTR_HALT;
	} while ((val == JRINTR_HALT_ONGOING) && --timeout);

	if (!timeout)
		return CAAM_BUSY;

	return CAAM_NO_ERROR;
}

void caam_hal_jr_resume(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRX_JRINTR, JRINTR_HALT_RESUME);

	caam_hal_jr_enable_itr(baseaddr);
}

uint8_t caam_hal_jr_input_index(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRX_IRRIR) >> 2;
}

uint8_t caam_hal_jr_output_index(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRX_ORWIR) >> 3;
}
