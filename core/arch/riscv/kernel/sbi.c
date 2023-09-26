// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022 NXP
 */

#include <kernel/panic.h>
#include <riscv.h>
#include <sbi.h>
#include <tee/optee_abi.h>
#include <tee/teeabi.h>
#include <tee/teeabi_opteed.h>
#include <tee/teeabi_opteed_macros.h>

struct sbiret {
	long error;
	long value;
};

#define _sbi_ecall(ext, fid, arg0, arg1, arg2, arg3, arg4, arg5, ...) ({  \
	register unsigned long a0 asm("a0") = (unsigned long)arg0; \
	register unsigned long a1 asm("a1") = (unsigned long)arg1; \
	register unsigned long a2 asm("a2") = (unsigned long)arg2; \
	register unsigned long a3 asm("a3") = (unsigned long)arg3; \
	register unsigned long a4 asm("a4") = (unsigned long)arg4; \
	register unsigned long a5 asm("a5") = (unsigned long)arg5; \
	register unsigned long a6 asm("a6") = (unsigned long)fid;  \
	register unsigned long a7 asm("a7") = (unsigned long)ext;  \
	asm volatile ("ecall" \
		: "+r" (a0), "+r" (a1) \
		: "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r"(a6), "r"(a7) \
		: "memory"); \
	(struct sbiret){ .error = a0, .value = a1 }; \
})

#define sbi_ecall(...) _sbi_ecall(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)

void sbi_console_putchar(int ch)
{
	sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, (unsigned long)ch);
}

int sbi_boot_hart(uint32_t hart_id, paddr_t start_addr, unsigned long arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hart_id, start_addr, arg);

	return ret.error;
}

void __noreturn __naked teeabi_return_to_ree(unsigned long arg0,
					     unsigned long arg1,
					     unsigned long arg2,
					     unsigned long arg3,
					     unsigned long arg4,
					     unsigned long arg5)
{
	_sbi_ecall(SBI_EXT_TEE, 0, arg0, arg1, arg2, arg3, arg4, arg5);

	/* Should not be here. */
	panic();
}
