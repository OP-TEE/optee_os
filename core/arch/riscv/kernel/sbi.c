// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <riscv.h>
#include <sbi.h>

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

/**
 * sbi_hsm_hart_start() - Start target hart at OP-TEE entry in S-mode
 * @hartid:     Target hart ID
 * @start_addr: Physical address of OP-TEE entry
 * @arg:        opaque parameter, typically used as the physical
 *              address of device-tree passed via @arg->a1
 *
 * Return:      SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_start(uint32_t hartid, paddr_t start_addr, unsigned long arg)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid, start_addr,
			arg);

	return ret.error;
}

/**
 * sbi_hsm_hart_get_status() - Get the current HSM state of given hart
 * @hartid:         Target hart ID
 * @status:         Pointer to store HSM state
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_hsm_hart_get_status(uint32_t hartid, enum sbi_hsm_hart_state *status)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_GET_STATUS, hartid);

	if (ret.error)
		return ret.error;

	*status = ret.value;
	return SBI_SUCCESS;
}
