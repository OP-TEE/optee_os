// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Power state management.
 */
#include <caam_common.h>
#include <caam_hal_clk.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_pwr.h>
#include <malloc.h>
#include <kernel/pm.h>
#include <kernel/panic.h>

static SLIST_HEAD(,
		  backup_data) data_list = SLIST_HEAD_INITIALIZER(backup_data);

/*
 * Add definition of the backup data in the list
 *
 * @baseaddr  Register base address
 * @regs      Register list
 * @nbentries Number of entries in the list
 */
void caam_pwr_add_backup(vaddr_t baseaddr, const struct reglist *regs,
			 size_t nbentries)
{
	struct backup_data *newelem = NULL;
	struct backup_data *elem = NULL;

	uint32_t idx = 0;
	uint32_t nbregs = 0;

	newelem = malloc(sizeof(struct backup_data));
	if (!newelem)
		panic();

	/* Count the number of registers to save/restore */
	for (idx = 0; idx < nbentries; idx++)
		nbregs += regs[idx].nbregs;

	newelem->baseaddr = baseaddr;
	newelem->nbentries = nbentries;
	newelem->regs = regs;
	newelem->val = malloc(nbregs * sizeof(*newelem->val));

	if (!newelem->val)
		panic();

	elem = SLIST_FIRST(&data_list);
	if (elem) {
		while (SLIST_NEXT(elem, next))
			elem = SLIST_NEXT(elem, next);

		SLIST_INSERT_AFTER(elem, newelem, next);
	} else {
		SLIST_INSERT_HEAD(&data_list, newelem, next);
	}
}

/* Backup all registers present in the data_list */
static void do_save_regs(void)
{
	struct backup_data *elem = NULL;
	const struct reglist *reg = NULL;
	uint32_t idx = 0;
	uint32_t validx = 0;
	uint32_t regidx = 0;

	SLIST_FOREACH(elem, &data_list, next)
	{
		reg = elem->regs;
		validx = 0;
		for (idx = 0; idx < elem->nbentries; idx++, reg++) {
			for (regidx = 0; regidx < reg->nbregs;
			     regidx++, validx++) {
				elem->val[validx] =
					io_caam_read32(elem->baseaddr +
							reg->offset +
							(4 * regidx));
				elem->val[validx] &= ~reg->mask_clr;

				PWR_TRACE("Save @0x%" PRIxPTR "=0x%" PRIx32,
					  (elem->baseaddr + reg->offset +
					   (4 * regidx)),
					  elem->val[validx]);
			}
		}
	}
}

/* Restore all registers present in the data_list */
static void do_restore_regs(void)
{
	struct backup_data *elem = NULL;
	const struct reglist *reg = NULL;
	uint32_t idx = 0;
	uint32_t validx = 0;
	uint32_t regidx = 0;

	SLIST_FOREACH(elem, &data_list, next)
	{
		reg = elem->regs;
		validx = 0;
		for (idx = 0; idx < elem->nbentries; idx++, reg++) {
			for (regidx = 0; regidx < reg->nbregs;
			     regidx++, validx++) {
				PWR_TRACE("Restore @0x%" PRIxPTR "=0x%" PRIx32,
					  elem->baseaddr + reg->offset +
						  (4 * regidx),
					  elem->val[validx]);
				io_caam_write32((elem->baseaddr + reg->offset +
						 (4 * regidx)),
						elem->val[validx] |
							reg->mask_set);
			}
		}
	}
}

/*
 * CAAM Power state preparation/entry
 *
 * @mode    Power mode to reach
 * @wait    wait until power state is ready
 */
static TEE_Result pm_enter(uint32_t pm_hint)
{
	enum CAAM_Status ret = CAAM_BUSY;

	PWR_TRACE("CAAM power mode %d entry", pm_hint);

	if (pm_hint == PM_HINT_CLOCK_STATE) {
		ret = caam_jr_halt();
	} else if (pm_hint == PM_HINT_CONTEXT_STATE) {
		do_save_regs();
		ret = caam_jr_flush();
	}

	return (ret == CAAM_BUSY) ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

/*
 * CAAM Power state resume
 *
 * @mode    Power mode to resume from
 */
static TEE_Result pm_resume(uint32_t pm_hint)
{
	PWR_TRACE("CAAM power mode %d resume", pm_hint);
	if (pm_hint == PM_HINT_CONTEXT_STATE) {
		/* Enable the CAAM Clock */
		caam_hal_clk_enable(true);
		do_restore_regs();
		caam_jr_resume(pm_hint);
	} else {
		caam_jr_resume(pm_hint);
	}

	return TEE_SUCCESS;
}

/*
 * Power Management Callback function executed when system enter or resume
 * from a power mode
 *
 * @op        Operation mode SUSPEND/RESUME
 * @pm_hint   Power mode type
 * @pm_handle Driver private handle (not used)
 */
static TEE_Result
pm_enter_resume(enum pm_op op, uint32_t pm_hint,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		return pm_enter(pm_hint);
	else
		return pm_resume(pm_hint);
}

/*
 * Power Initialization function called when all CAAM modules are
 * initialized correctly.
 * Register the PM callback in the system.
 */
void caam_pwr_init(void)
{
	register_pm_driver_cb(pm_enter_resume, NULL);
}
