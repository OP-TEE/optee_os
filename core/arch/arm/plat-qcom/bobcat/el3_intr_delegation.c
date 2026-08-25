// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <el3_intr_delegation.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/thread.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

static const uint32_t el3_delegated_interrupts[] = {
	NON_SEC_WDOG_BITE_INT_ID,
	XPU_VIOLATION_INT_ID,
	RESET_SGI_INT_ID,
	MEMNOC_ERROR_INT_ID,
	C1_NOC_ERROR_INT_ID,
	C2_NOC_ERROR_INT_ID,
	SNOC_ERROR_INT_ID,
	NSS_NOC_ERROR_INT_ID,
};

/*
 * QCOM_EL3_INTR_DELEGATION_SVC_ID is a Qualcomm-private SMC64 fast call,
 * not defined in any upstream TF-A ABI:
 *   a0 (in):  QCOM_EL3_INTR_DELEGATION_SVC_ID
 *   a1 (in):  GIC interrupt ID being delegated
 *   a0 (out): 0 on success, non-zero if TF-A failed to service the
 *             interrupt at its source
 */
static enum itr_return handle_el3_delegated_interrupt(struct itr_handler *h)
{
	struct thread_smc_args args = {
		.a0 = QCOM_EL3_INTR_DELEGATION_SVC_ID,
		.a1 = h->it,
	};

	thread_smccc(&args);
	if (args.a0)
		EMSG("TF-A failed to service delegated interrupt %zu: %#"PRIx64,
		     h->it, args.a0);

	return ITRR_HANDLED;
}

/*
 * RESET_SGI_INT_ID is an SGI: its GIC enable bit is banked per-CPU, so it
 * must be (re-)enabled on every core, not just the one that runs
 * service_init(). The other delegated IDs are SPIs, enabled globally, so
 * re-enabling them here as well is harmless.
 */
static void el3_intr_delegation_enable_all(struct itr_chip *chip)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(el3_delegated_interrupts); n++)
		interrupt_enable(chip, el3_delegated_interrupts[n]);
}

void el3_intr_delegation_init_per_cpu(void)
{
	if (IS_ENABLED2(_CFG_ARM_GIC_V3_OR_V4))
		return;

	el3_intr_delegation_enable_all(interrupt_get_main_chip());
}

static TEE_Result register_el3_delegated_interrupts(void)
{
	struct itr_chip *chip = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t n = 0;

	/*
	 * This driver works around GICv2 exposing a single secure
	 * interrupt group: GICv3/v4 platforms route to TF-A directly
	 * and don't need it.
	 */
	if (IS_ENABLED2(_CFG_ARM_GIC_V3_OR_V4))
		return TEE_SUCCESS;

	chip = interrupt_get_main_chip();
	for (n = 0; n < ARRAY_SIZE(el3_delegated_interrupts); n++) {
		res = interrupt_create_handler(chip,
					       el3_delegated_interrupts[n],
					       handle_el3_delegated_interrupt,
					       0, 0, NULL);
		if (res)
			return res;
	}

	el3_intr_delegation_enable_all(chip);

	return TEE_SUCCESS;
}
service_init(register_el3_delegated_interrupts);
