// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022,2026 NXP
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

/**
 * sbi_remote_fence_i() - Execute FENCE.I on remote harts
 * @hart_mask:      Bit-vector of target hart IDs, relative to @hart_mask_base
 * @hart_mask_base: First hart ID covered by @hart_mask, or
 *                  SBI_HART_MASK_BASE_ALL to target every hart available
 *                  to the supervisor
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_remote_fence_i(unsigned long hart_mask, unsigned long hart_mask_base)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_FENCE_I,
			hart_mask, hart_mask_base);

	return ret.error;
}

/**
 * sbi_remote_sfence_vma() - Execute SFENCE.VMA on remote harts
 * @hart_mask:      Bit-vector of target hart IDs, relative to @hart_mask_base
 * @hart_mask_base: First hart ID covered by @hart_mask, or
 *                  SBI_HART_MASK_BASE_ALL to target every hart available
 *                  to the supervisor
 * @start_addr:     First virtual address of the range to fence
 * @size:           Size of the range to fence
 *
 * The whole address space is fenced when @start_addr and @size are both 0,
 * or when @size is -1 (SBI spec, "RFENCE Extension").
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_remote_sfence_vma(unsigned long hart_mask, unsigned long hart_mask_base,
			  unsigned long start_addr, unsigned long size)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
			hart_mask, hart_mask_base, start_addr, size);

	return ret.error;
}

/**
 * sbi_remote_sfence_vma_asid() - Execute SFENCE.VMA with ASID on remote harts
 * @hart_mask:      Bit-vector of target hart IDs, relative to @hart_mask_base
 * @hart_mask_base: First hart ID covered by @hart_mask, or
 *                  SBI_HART_MASK_BASE_ALL to target every hart available
 *                  to the supervisor
 * @start_addr:     First virtual address of the range to fence
 * @size:           Size of the range to fence
 * @asid:           Address space identifier to fence
 *
 * The whole address space of @asid is fenced when @start_addr and @size
 * are both 0, or when @size is -1 (SBI spec, "RFENCE Extension").
 *
 * Return:          SBI error code (SBI_SUCCESS = 0 on success)
 */
int sbi_remote_sfence_vma_asid(unsigned long hart_mask,
			       unsigned long hart_mask_base,
			       unsigned long start_addr, unsigned long size,
			       unsigned long asid)
{
	struct sbiret ret = { };

	ret = sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID,
			hart_mask, hart_mask_base, start_addr, size, asid);

	return ret.error;
}
