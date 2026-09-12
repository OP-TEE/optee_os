// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/thread.h>
#include <platform_config.h>
#include <tee_api_types.h>
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

static enum itr_return handle_el3_delegated_interrupt(struct itr_handler *h)
{
	struct thread_smc_args args = {
		.a0 = QCOM_EL3_INTR_DELEGATION_SVC_ID,
		.a1 = h->it,
	};

	thread_smccc(&args);

	return ITRR_HANDLED;
}

static TEE_Result register_el3_delegated_interrupts(void)
{
	struct itr_chip *chip = interrupt_get_main_chip();
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(el3_delegated_interrupts); n++) {
		res = interrupt_create_handler(chip,
					       el3_delegated_interrupts[n],
					       handle_el3_delegated_interrupt,
					       0, 0, NULL);
		if (res)
			return res;

		interrupt_enable(chip, el3_delegated_interrupts[n]);
	}

	return TEE_SUCCESS;
}
service_init(register_el3_delegated_interrupts);
