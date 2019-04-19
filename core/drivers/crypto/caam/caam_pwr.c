// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_pwr.c
 *
 * @brief   CAAM Power state management.
 */

/* Global includes */
#include <malloc.h>
#include <kernel/pm.h>
#include <kernel/panic.h>

/* Local includes */
#include "caam_common.h"
#include "caam_io.h"
#include "caam_jr.h"
#include "caam_pwr.h"

/* Hal includes */
#include "hal_clk.h"

static SLIST_HEAD(, backup_data) data_list =
		SLIST_HEAD_INITIALIZER(backup_data);

/**
 * @brief   Add definition of the backup data in the list
 *
 * @param[in] baseaddr  Register base address
 * @param[in] regs      Register list
 * @param[in] nbEntries Number of entries in the list
 */
void caam_pwr_add_backup(vaddr_t baseaddr, const struct reglist *regs,
		size_t nbEntries)
{
	struct backup_data *newelem;
	struct backup_data *elem;

	uint32_t idx;
	uint32_t nbRegs = 0;

	newelem = malloc(sizeof(struct backup_data));
	if (!newelem)
		panic();

	/* Count the number of registers to save/restore */
	for (idx = 0; idx < nbEntries; idx++)
		nbRegs += regs[idx].nbRegs;

	newelem->baseaddr  = baseaddr;
	newelem->nbEntries = nbEntries;
	newelem->regs      = regs;
	newelem->val       = malloc(nbRegs * sizeof(*newelem->val));

	if (!newelem->val)
		panic();

	elem = SLIST_FIRST(&data_list);
	if (elem) {
		while (SLIST_NEXT(elem, next))
			elem = SLIST_NEXT(elem, next);

		SLIST_INSERT_AFTER(elem, newelem, next);
	} else
		SLIST_INSERT_HEAD(&data_list, newelem, next);
}

/**
 * @brief   backup all registers present in the data_list
 *
 */
static void do_save_regs(void)
{
	struct backup_data   *elem;
	const struct reglist *reg;
	uint32_t idx;
	uint32_t validx;
	uint32_t regidx;

	SLIST_FOREACH(elem, &data_list, next) {
		reg = elem->regs;
		validx = 0;
		for (idx = 0; idx < elem->nbEntries; idx++, reg++) {
			for (regidx = 0; regidx < reg->nbRegs;
				regidx++, validx++) {
				elem->val[validx] = io_caam_read32(
						elem->baseaddr +
						reg->offset + (4 * regidx));
				elem->val[validx] &= ~reg->mask_clr;
				PWR_TRACE("Save @0x%"PRIxPTR"=0x%"PRIx32"",
				elem->baseaddr + reg->offset + (4 * regidx),
				elem->val[validx]);
			}
		}
	}
}

/**
 * @brief   restore all registers present in the data_list
 *
 */
static void do_restore_regs(void)
{
	struct backup_data   *elem;
	const struct reglist *reg;
	uint32_t idx;
	uint32_t validx;
	uint32_t regidx;

	SLIST_FOREACH(elem, &data_list, next) {
		reg = elem->regs;
		validx = 0;
		for (idx = 0; idx < elem->nbEntries; idx++, reg++) {
			for (regidx = 0; regidx < reg->nbRegs;
				regidx++, validx++) {
				PWR_TRACE("Restore @0x%"PRIxPTR"=0x%"PRIx32"",
				elem->baseaddr + reg->offset + (4 * regidx),
				elem->val[validx]);
				io_caam_write32(
					(elem->baseaddr + reg->offset +
					 (4 * regidx)),
					elem->val[validx] | reg->mask_set);

			}
		}
	}
}

/**
 * @brief   CAAM Power state preparation/entry
 *
 * @param[in] mode    Power mode to reach
 * @param[in] wait    wait until power state is ready
 *
 * @retval TEE_SUCCESS       Success
 * @retval TEE_ERROR_GENERIC Generic error
 */
static TEE_Result pm_enter(uint32_t pm_hint)
{
	int ret = (-1);

	PWR_TRACE("CAAM power mode %d entry", pm_hint);

	if (pm_hint == PM_HINT_CLOCK_STATE)
		ret = caam_jr_halt();
	else if (pm_hint == PM_HINT_CONTEXT_STATE) {
		do_save_regs();
		ret = caam_jr_flush();
	}

	return (ret == (-1)) ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

/**
 * @brief   CAAM Power state resume
 *
 * @param[in] mode    Power mode to resume from
 *
 */
static TEE_Result pm_resume(uint32_t pm_hint)
{
	PWR_TRACE("CAAM power mode %d resume", pm_hint);
	if (pm_hint == PM_HINT_CONTEXT_STATE) {
		/* Enable the CAAM Clock */
		hal_clk_enable(true);
		do_restore_regs();
		caam_jr_resume(pm_hint);
	} else
		caam_jr_resume(pm_hint);

	return TEE_SUCCESS;
}

/**
 * @brief   Power Management Callback function executed when system
 *          enter or resume from a power mode
 *
 * @param[in] op        Operation mode SUSPEND/RESUME
 * @param[in] pm_hint   Power mode type
 * @param[in] pm_handle Driver private handle (not used)
 *
 * @retval TEE_SUCCESS       Success
 * @retval TEE_GENERIC_ERROR Error during power procedure
 */
static TEE_Result pm_enter_resume(enum pm_op op, uint32_t pm_hint,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		return pm_enter(pm_hint);
	else
		return pm_resume(pm_hint);
}

/**
 * @brief   Power Initialization function called when all CAAM modules
 *          are initialized correctly.
 *          Register the PM callback in the system
 */
void caam_pwr_init(void)
{
	register_pm_driver_cb(pm_enter_resume, NULL);
}

