// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <platform_config.h>
#include <qcom_common.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

/*
 * GICv2 has a single secure interrupt group, so interrupts owned by TF-A
 * trap into OP-TEE first and are handed back to TF-A with an SMC.
 */

static const uint32_t delegated_spis[] = {
	QCOM_WDT_BITE_INT_ID,
	QCOM_XPU_VIOLATION_INT_ID,
	QCOM_MEMNOC_ERROR_INT_ID,
	QCOM_CNOC0_ERROR_INT_ID,
	QCOM_CNOC1_ERROR_INT_ID,
	QCOM_SNOC_ERROR_INT_ID,
	QCOM_NSS_NOC_ERROR_INT_ID,
};

/*
 * QCOM_EL3_INTR_DELEGATION_SVC_ID is a Qualcomm-private SiP service call:
 *   a0 (in):  QCOM_EL3_INTR_DELEGATION_SVC_ID
 *   a1 (in):  GIC interrupt ID being delegated
 *   a0 (out): 0 if TF-A handled the call, non-zero if it is not supported
 *   a1 (out): 0 if TF-A serviced the interrupt at its source, otherwise a
 *             negative errno value
 *
 * A failed call is not retried: nothing would change for the next attempt
 * and the interrupt would fire again forever. Report it as unhandled instead
 * so the interrupt framework masks the source.
 */
static enum itr_return
qcom_gicv2_el3_intr_delegation_handler(struct itr_handler *h)
{
	struct thread_smc_args args = {
		.a0 = QCOM_EL3_INTR_DELEGATION_SVC_ID,
		.a1 = h->it,
	};

	thread_smccc(&args);
	if (args.a0 || args.a1) {
		EMSG("TF-A failed on interrupt %zu: %#"PRIx64" %#"PRIx64,
		     h->it, (uint64_t)args.a0, (uint64_t)args.a1);
		return ITRR_NONE;
	}

	return ITRR_HANDLED;
}

/* The reset SGI's GIC enable bit is banked per-CPU: enable it on every core */
void qcom_gicv2_el3_intr_delegation_init_per_cpu(void)
{
	interrupt_enable(interrupt_get_main_chip(), QCOM_RESET_SGI_INT_ID);
}

static void qcom_gicv2_el3_intr_delegation_register(struct itr_chip *chip,
						    size_t it)
{
	TEE_Result res = interrupt_create_handler(chip, it,
				qcom_gicv2_el3_intr_delegation_handler,
				0, 0, NULL);

	if (res)
		panic("GICv2 EL3 interrupt delegation init failed");
}

/* Register before native interrupts are unmasked, so none gets masked */
void qcom_gicv2_el3_intr_delegation_init(void)
{
	struct itr_chip *chip = interrupt_get_main_chip();
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(delegated_spis); n++) {
		qcom_gicv2_el3_intr_delegation_register(chip,
							delegated_spis[n]);
		interrupt_enable(chip, delegated_spis[n]);
	}
	qcom_gicv2_el3_intr_delegation_register(chip, QCOM_RESET_SGI_INT_ID);

	/* Other cores do it from boot_secondary_init_intc() */
	qcom_gicv2_el3_intr_delegation_init_per_cpu();
}
