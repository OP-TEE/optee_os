// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/unwind.h>
#include <trace.h>

/* SGI number chosen to halt other cores must be in the secure SGI range */
static_assert(!IS_ENABLED(CFG_HALT_CORES_ON_PANIC) ||
	      (CFG_HALT_CORES_ON_PANIC_SGI >= 8 &&
	       CFG_HALT_CORES_ON_PANIC_SGI < 16));

static enum itr_return __noreturn
multi_core_panic_it_handler(struct itr_handler *hdl __unused)
{
	IMSG("Halting CPU %zu", get_core_pos());

	while (true)
		cpu_idle();
}

static struct itr_handler multi_core_panic_handler __nex_data = {
	.it = CFG_HALT_CORES_ON_PANIC_SGI,
	.handler = multi_core_panic_it_handler,
};
DECLARE_KEEP_PAGER(multi_core_panic_handler);

static void notify_other_cores(void)
{
	struct itr_chip *chip = interrupt_get_main_chip_may_fail();

	if (chip)
		interrupt_raise_sgi(chip, CFG_HALT_CORES_ON_PANIC_SGI,
				    ITR_CPU_MASK_TO_OTHER_CPUS);
	else
		EMSG("Can't notify other cores, main interrupt chip not set");
}

static TEE_Result init_multi_core_panic_handler(void)
{
	if (!IS_ENABLED(CFG_HALT_CORES_ON_PANIC) || CFG_TEE_CORE_NB_CORE == 1)
		return TEE_SUCCESS;

	if (interrupt_add_handler_with_chip(interrupt_get_main_chip(),
					    &multi_core_panic_handler))
		panic();

	interrupt_enable(interrupt_get_main_chip(),
			 multi_core_panic_handler.it);

	return TEE_SUCCESS;
}

nex_driver_init_late(init_multi_core_panic_handler);

void __do_panic(const char *file __maybe_unused,
		const int line __maybe_unused,
		const char *func __maybe_unused,
		const char *msg __maybe_unused)
{
	/* disable preemption */
	(void)thread_mask_exceptions(THREAD_EXCP_ALL);

	/* trace: Panic ['panic-string-message' ]at FILE:LINE [<FUNCTION>]" */
	if (!file && !func && !msg)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic %s%s%sat %s:%d %s%s%s",
			 msg ? "'" : "", msg ? msg : "", msg ? "' " : "",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	print_kernel_stack();

	if (IS_ENABLED(CFG_HALT_CORES_ON_PANIC) && CFG_TEE_CORE_NB_CORE > 1)
		notify_other_cores();

	/* abort current execution */
	while (1)
		cpu_idle();
}

void __weak cpu_idle(void)
{
}
