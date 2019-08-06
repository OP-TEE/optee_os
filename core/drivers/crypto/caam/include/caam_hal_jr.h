/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Job Rings Hardware Abstration Layer header.
 */
#ifndef __CAAM_HAL_JR_H__
#define __CAAM_HAL_JR_H__

/*
 * Configures the Job Ring Owner and lock it.
 * If the configuration is already locked, checks the configuration
 * set and returns an error if value is not corresponding to the
 * expected value.
 *
 * @ctrl_base  Base address of the controller
 * @jr_offset  Job Ring offset to configure
 * @owner      Onwer ID to configure
 */
enum caam_status caam_hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
				      enum caam_jr_owner owner);

/*
 * Resets the Job Ring to ensure that all pending jobs are completed
 * and no other will be executed
 *
 * @baseaddr   Job Ring Base address
 */
enum caam_status caam_hal_jr_reset(vaddr_t baseaddr);

/*
 * Configures the Job Ring HW queues.
 *
 * @baseaddr   Job Ring Base Address
 * @nbjobs     Number of job rings supported
 * @inrings    physical address of the JR input queue
 * @outrings   physical address of the JR output queue
 */
void caam_hal_jr_config(vaddr_t baseaddr, uint8_t nbjobs, uint64_t inrings,
			uint64_t outrings);

/*
 * Returns the number of slots available in the input job ring
 *
 * @baseaddr   Job Ring Base address
 */
uint32_t caam_hal_jr_read_nbslot_available(vaddr_t baseaddr);

/*
 * Indicates to HW that a new job is available
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_add_newjob(vaddr_t baseaddr);

/*
 * Returns the number of job completed and present in the output ring slots
 *
 * @baseaddr   Job Ring Base Address
 */
uint32_t caam_hal_jr_get_nbjob_done(vaddr_t baseaddr);

/*
 * Removes a job from the job ring output queue
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_del_job(vaddr_t baseaddr);

/*
 * Disable and acknwoledge the Job Ring interrupt
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_disable_itr(vaddr_t baseaddr);

/*
 * Enable the Job Ring interrupt
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_enable_itr(vaddr_t baseaddr);

/*
 * If an interrupt is pending, acknowledges it and returns true.
 *
 * @baseaddr   Job Ring Base Address
 */
bool caam_hal_jr_check_ack_itr(vaddr_t baseaddr);

/*
 * Halt the Job Ring processing. Stop fetching input queue and wait
 * all running jobs normal completion.
 *
 * @baseaddr   Job Ring Base Address
 */
enum caam_status caam_hal_jr_halt(vaddr_t baseaddr);

/*
 * Wait all Input queue Job Ring processing.
 *
 * @baseaddr   Job Ring Base Address
 */
enum caam_status caam_hal_jr_flush(vaddr_t baseaddr);

/*
 * Resume the Job Ring processing.
 *
 * @baseaddr   Job Ring Base Address
 */
void caam_hal_jr_resume(vaddr_t baseaddr);

/*
 * Returns the next entry free in the JR input queue.
 * The HW increments register by 4. Convert it to a software index number
 *
 * @baseaddr   CAAM JR Base Address
 */
uint8_t caam_hal_jr_input_index(vaddr_t baseaddr);

/*
 * Returns the next entry to read from the JR output queue.
 * The HW increments register by 8. Convert it to a software index number
 *
 * @baseaddr   CAAM JR Base Address
 */
uint8_t caam_hal_jr_output_index(vaddr_t baseaddr);

/*
 * Let the JR prepare data that need backup
 *
 * @ctrl_base   CAAM JR Base Address
 * @jr_offset   Job Ring offset to prepare backup for
 */
void caam_hal_jr_prepare_backup(vaddr_t ctrl_base, paddr_t jr_offset);

#endif /* __CAAM_HAL_JR_H__ */
