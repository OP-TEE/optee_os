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

/*
 * List of common JR registers to save/restore
 */
const struct reglist jr_backup[] = {
	{ JRx_IRBAR, 2, 0, 0 },
	{ JRx_IRSR, 1, 0, 0 },
	{ JRx_ORBAR, 2, 0, 0 },
	{ JRx_ORSR, 1, 0, 0 },
	{ JRx_JRCFGR_LS, 1, 0, 0 },
};

/*
 * Resets the Job Ring to ensure that all pending job completed
 * and no other will be executed
 *
 * @baseaddr   Job Ring Base address
 */
enum CAAM_Status caam_hal_jr_reset(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t reg_val = 0;

	/*
	 * Reset is done in 2 steps:
	 *  - Flush all pending jobs (Set RESET bit)
	 *  - Reset the Job Ring (Set RESET bit second time)
	 */

	/* Mask interrupts to poll for reset completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
		  JRx_JRCFGR_LS_IMSK);

	/* Initiate flush (required prior to reset) */
	io_caam_write32(baseaddr + JRx_JRCR, JRx_JRCR_RESET);

	do {
		caam_udelay(100);
		reg_val = io_caam_read32(baseaddr + JRx_JRINTR);
		reg_val &= BM_JRx_JRINTR_HALT;
	} while ((reg_val == JRINTR_HALT_ONGOING) && --timeout);

	if (!timeout || reg_val != JRINTR_HALT_DONE) {
		EMSG("Failed to flush job ring\n");
		return CAAM_FAILURE;
	}

	/* Initiate reset */
	timeout = 100;
	io_caam_write32(baseaddr + JRx_JRCR, JRx_JRCR_RESET);
	do {
		caam_udelay(100);
		reg_val = io_caam_read32(baseaddr + JRx_JRCR);
	} while ((reg_val & JRx_JRCR_RESET) && --timeout);

	if (!timeout) {
		EMSG("Failed to reset job ring\n");
		return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

/*
 * Configures the Job Ring HW queues.
 * Returns the number of jobs complete.
 *
 * @baseaddr   Job Ring Base Address
 * @nbjobs     Number of job rings supported
 * @inrings    physical address of the JR input queue
 * @outrings   physical address of the JR output queue
 */
void caam_hal_jr_config(vaddr_t baseaddr, uint8_t nbjobs, uint64_t inrings,
			uint64_t outrings)
{
	uint32_t value = 0;

	/* Setup the JR input queue */
	io_caam_write32(baseaddr + JRx_IRBAR, ((inrings >> 32) & 0xFFFFFFFF));
	io_caam_write32(((baseaddr + JRx_IRBAR) + 4), (inrings & 0xFFFFFFFF));
	io_caam_write32(baseaddr + JRx_IRSR, nbjobs);

	/* Setup the JR output queue */
	io_caam_write32(baseaddr + JRx_ORBAR, ((outrings >> 32) & 0xFFFFFFFF));
	io_caam_write32(((baseaddr + JRx_ORBAR) + 4), (outrings & 0xFFFFFFFF));
	io_caam_write32(baseaddr + JRx_ORSR, nbjobs);

	/* Disable the JR interrupt */
	caam_hal_jr_disable_itr(baseaddr);

	/*
	 * Configure interrupts but disable it:
	 * Optimization to generate an interrupt either when there are
	 *   half of the job done
	 *   or when there is a job done and 10 clock cycles elapse without new
	 *      job complete
	 */
	value = JRx_JRCFGR_LS_ICTT(10);
	value |= JRx_JRCFGR_LS_ICDCT((nbjobs / 2));
	value |= JRx_JRCFGR_LS_ICEN;
	value |= JRx_JRCFGR_LS_IMSK;
	io_caam_write32(baseaddr + JRx_JRCFGR_LS, (uint32_t)value);

#ifdef CFG_CRYPTO_DRIVER
	caam_pwr_add_backup(baseaddr, jr_backup, ARRAY_SIZE(jr_backup));
#endif
}

/*
 * Returns the number of slots available in the input job ring
 *
 * @baseaddr   Job Ring Base address
 */
uint32_t caam_hal_jr_read_nbslot_available(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRx_IRSAR);
}

/*
 * Indicates to HW that a new job is available
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_add_newjob(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRx_IRJAR, 1);
}

/*
 * Returns the number of job complete and present in the output ring slots
 *
 * @baseaddr   Job Ring Base Address
 */
uint32_t caam_hal_jr_get_nbjob_done(vaddr_t baseaddr)
{
	return io_caam_read32(baseaddr + JRx_ORSFR);
}

/*
 * Removes a job from the job ring output queue
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_del_job(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRx_ORJRR, 1);
}

/*
 * Disable and acknwoledge the Job Ring interrupt
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_disable_itr(vaddr_t baseaddr)
{
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
		  JRx_JRCFGR_LS_IMSK);
	io_mask32(baseaddr + JRx_JRINTR, JRx_JRINTR_JRI, JRx_JRINTR_JRI);
}

/*
 * Enable the Job Ring interrupt
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_enable_itr(vaddr_t baseaddr)
{
	io_mask32(baseaddr + JRx_JRCFGR_LS, ~JRx_JRCFGR_LS_IMSK,
		  JRx_JRCFGR_LS_IMSK);
}

/*
 * Pool and acknowledge the Job Ring interrupt
 * Returns true if an interrupt is pending.
 *
 * @baseaddr   Job Ring Base Address
 */
bool caam_hal_jr_poolack_itr(vaddr_t baseaddr)
{
	uint32_t val = 0;

	val = io_caam_read32(baseaddr + JRx_JRINTR);

	if ((val & JRx_JRINTR_JRI) == JRx_JRINTR_JRI) {
		/* Acknowledge interrupt */
		io_mask32(baseaddr + JRx_JRINTR, JRx_JRINTR_JRI,
			  JRx_JRINTR_JRI);
		return true;
	}

	return false;
}

/*
 * Halt the Job Ring processing. Stop fetching input queue and wait
 * all running jobs normal completion.
 *
 * @baseaddr   Job Ring Base Address
 */
enum CAAM_Status caam_hal_jr_halt(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val = 0;

	/* Mask interrupts to poll for completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
		  JRx_JRCFGR_LS_IMSK);

	/* Request Job ring halt */
	io_caam_write32(baseaddr + JRx_JRCR, JRx_JRCR_PARK);

	/* Check if there is a job running */
	val = io_caam_read32(baseaddr + JRx_IRSR);
	if ((caam_hal_jr_read_nbslot_available(baseaddr) == val) &&
	    (io_caam_read32(baseaddr + JRx_CSTA) != JRx_CSTA_BSY))
		return CAAM_NO_ERROR;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = io_caam_read32(baseaddr + JRx_JRINTR);
		val &= BM_JRx_JRINTR_HALT;
	} while ((val != JRINTR_HALT_DONE) && --timeout);

	if (!timeout)
		return CAAM_BUSY;

	return CAAM_NO_ERROR;
}

/*
 * Wait all Input queue Job Ring processing.
 *
 * @baseaddr   Job Ring Base Address
 */
enum CAAM_Status caam_hal_jr_flush(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val = 0;

	/* Mask interrupts to poll for completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
		  JRx_JRCFGR_LS_IMSK);

	/* Request Job ring to flush input queue */
	io_caam_write32(baseaddr + JRx_JRCR, JRx_JRCR_RESET);

	/* Check if there is a job running */
	val = io_caam_read32(baseaddr + JRx_IRSR);
	if ((caam_hal_jr_read_nbslot_available(baseaddr) == val) &&
	    (io_caam_read32(baseaddr + JRx_CSTA) != JRx_CSTA_BSY))
		return CAAM_NO_ERROR;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = io_caam_read32(baseaddr + JRx_JRINTR);
		val &= BM_JRx_JRINTR_HALT;
	} while ((val == JRINTR_HALT_DONE) && --timeout);

	if (!timeout)
		return CAAM_BUSY;

	return CAAM_NO_ERROR;
}

/*
 * Resume the Job Ring processing.
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_resume(vaddr_t baseaddr)
{
	io_caam_write32(baseaddr + JRx_JRINTR, JRINTR_HALT_RESUME);

	caam_hal_jr_enable_itr(baseaddr);
}

/*
 * Returns the next entry free in the JR input queue.
 * The HW increments register by 4. Convert it to a software index number
 *
 * @baseaddr   CAAM JR Base Address
 */
uint8_t caam_hal_jr_input_index(vaddr_t baseaddr)
{
	uint32_t index = 0;

	index = io_caam_read32(baseaddr + JRx_IRRIR);
	return index >> 2;
}

/*
 * Returns the next entry to read from the JR output queue.
 * The HW increments register by 8. Convert it to a software index number
 *
 * @baseaddr   CAAM JR Base Address
 */
uint8_t caam_hal_jr_output_index(vaddr_t baseaddr)
{
	uint32_t index = 0;

	index = io_caam_read32(baseaddr + JRx_ORWIR);
	return index >> 3;
}
