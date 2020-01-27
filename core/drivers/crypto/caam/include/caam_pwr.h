/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM driver common include file.
 *         Definition of the structure type to save and restore
 *         HW registers configuration
 */
#ifndef __CAAM_PWR_H__
#define __CAAM_PWR_H__

#include <sys/queue.h>

/*
 * Definition of the structure type used to list HW registers
 * to be saved and restored.
 */
struct reglist {
	uint32_t offset;   /* Register offset */
	uint32_t nbregs;   /* Number of consecutive registers */
	uint32_t mask_clr; /* Clear mask of bit to exclude in restore value */
	uint32_t mask_set; /* Set mask of bit to force in restore value */
};

#define BACKUP_REG(_offset, _nbregs, _mask_clr, _mask_set)                     \
	{                                                                      \
		.offset = _offset, .nbregs = _nbregs, .mask_clr = _mask_clr,   \
		.mask_set = _mask_set,                                         \
	}
/*
 * Definition of the structure type used to store registers to backup
 */
struct backup_data {
	vaddr_t baseaddr;           /* Register virtual base address */
	size_t nbentries;           /* Number of entries in the list */
	const struct reglist *regs; /* Register list */
	uint32_t *val;              /* Register value */

	SLIST_ENTRY(backup_data) next; /* Link to next data */
};

/*
 * Add definition of the backup data in the list
 *
 * @baseaddr  Register base address
 * @regs      Register list
 * @nbentries Number of entries in the list
 */
void caam_pwr_add_backup(vaddr_t baseaddr, const struct reglist *regs,
			 size_t nbentries);

/*
 * Power Initialization function called when all CAAM modules are
 * initialized correctly.
 * Register the PM callback in the system.
 */
void caam_pwr_init(void);

#endif /* __CAAM_PWR_H__ */
