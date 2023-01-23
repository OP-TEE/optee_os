// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019, 2021, 2023 NXP
 *
 * Brief   CAAM Power state management.
 */
#include <caam_common.h>
#include <caam_hal_clk.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_mp.h>
#include <caam_pwr.h>
#include <caam_status.h>
#include <caam_utils_status.h>
#include <kernel/pm.h>
#include <kernel/panic.h>
#include <malloc.h>

static SLIST_HEAD(,
		  backup_data) data_list = SLIST_HEAD_INITIALIZER(backup_data);

void caam_pwr_add_backup(vaddr_t baseaddr, const struct reglist *regs,
			 size_t nbentries)
{
	struct backup_data *newelem = NULL;
	struct backup_data *elem = NULL;
	uint32_t idx = 0;
	uint32_t nbregs = 0;

	newelem = malloc(sizeof(*newelem));
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

	/* Add the new backup data element at the end of the list */
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

	SLIST_FOREACH(elem, &data_list, next) {
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
					  elem->baseaddr + reg->offset +
						  4 * regidx,
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

	SLIST_FOREACH(elem, &data_list, next) {
		reg = elem->regs;
		validx = 0;
		for (idx = 0; idx < elem->nbentries; idx++, reg++) {
			for (regidx = 0; regidx < reg->nbregs;
			     regidx++, validx++) {
				PWR_TRACE("Restore @0x%" PRIxPTR "=0x%" PRIx32,
					  elem->baseaddr + reg->offset +
						  4 * regidx,
					  elem->val[validx]);
				io_caam_write32(elem->baseaddr + reg->offset +
							4 * regidx,
						elem->val[validx] |
							reg->mask_set);
			}
		}
	}
}

/*
 * CAAM Power state preparation/entry
 *
 * @pm_hint   Power mode type
 */
static TEE_Result pm_enter(uint32_t pm_hint)
{
	enum caam_status ret = CAAM_BUSY;

	PWR_TRACE("CAAM power mode %" PRIu32 " entry", pm_hint);

	if (pm_hint == PM_HINT_CLOCK_STATE) {
		ret = caam_jr_halt();
	} else if (pm_hint == PM_HINT_CONTEXT_STATE) {
		do_save_regs();
		ret = caam_jr_flush();
	}

	if (ret == CAAM_NO_ERROR)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_GENERIC;
}

/*
 * CAAM Power state resume
 *
 * @pm_hint   Power mode type
 */
static TEE_Result pm_resume(uint32_t pm_hint)
{
	enum caam_status ret = CAAM_FAILURE;

	PWR_TRACE("CAAM power mode %" PRIu32 " resume", pm_hint);
	if (pm_hint == PM_HINT_CONTEXT_STATE) {
		caam_hal_clk_enable(true);
		do_restore_regs();
	}

	caam_jr_resume(pm_hint);

	ret = caam_mp_resume(pm_hint);

	return caam_status_to_tee_result(ret);
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

void caam_pwr_init(void)
{
	register_pm_driver_cb(pm_enter_resume, NULL, "caam_pwr");
}
