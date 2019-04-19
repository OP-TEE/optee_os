/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    caam_pwr.h
 *
 * @brief   CAAM driver common include file.\n
 *          Definition of the structure type to save and restore
 *          HW registers configuration
 */

#ifndef __CAAM_PWR_H__
#define __CAAM_PWR_H__

/* Global includes */
#include <sys/queue.h>

/**
 * @brief   Definition of the structure type used to list HW registers
 *          to be saved and restored.
 */
struct reglist {
	uint32_t offset;   ///< Register offset
	uint32_t nbRegs;   ///< Number of consecutive registers
	uint32_t mask_clr; ///< Clear mask of bit to exclude in restore value
	uint32_t mask_set; ///< Set mask of bit to force in restore value
};

/**
 * @brief   Definition of the structure type used to store registers to
 *          backup
 */
struct backup_data {
	vaddr_t              baseaddr;  ///< Register virtual base address
	size_t               nbEntries; ///< Number of entries in the list
	const struct reglist *regs;     ///< Register list
	uint32_t             *val;      ///< Register value

	SLIST_ENTRY(backup_data) next;  ///< Link to the set of data in the list
};

/**
 * @brief   Add definition of the backup data in the list
 *
 * @param[in] baseaddr  Register base address
 * @param[in] regs      Register list
 * @param[in] nbEntries Number of entries in the list
 */
void caam_pwr_add_backup(vaddr_t baseaddr, const struct reglist *regs,
		size_t nbEntries);

/**
 * @brief   Power Initialization function called when all CAAM modules
 *          are initialized correctly.
 *          Register the PM callback in the system
 */
void caam_pwr_init(void);

#endif /* __CAAM_PWR_H__ */
