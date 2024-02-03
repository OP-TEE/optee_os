// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <riscv.h>
#include <sbi.h>

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

/**
 * sbi_probe_extension() - Check if an SBI extension ID is supported or not.
 * @extid: The extension ID to be probed.
 *
 * Return: 1 or an extension specific nonzero value if yes, 0 otherwise.
 */
int sbi_probe_extension(int extid)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid);
	if (!ret.error)
		return ret.value;

	return 0;
}

/**
 * sbi_console_putchar() - Writes given character to the console device.
 * @ch: The data to be written to the console.
 */
void sbi_console_putchar(int ch)
{
	sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch);
}

/**
 * sbi_dbcn_write_byte() - Write byte to debug console
 * @ch:         Byte to be written
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_dbcn_write_byte(unsigned char ch)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, ch);
	return ret.error;
}

int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid, start_addr,
			arg);

	return ret.error;
}
