// SPDX-License-Identifier: BSD-2-Clause
/*
 * SpacemiT K1 platform
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <riscv.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#ifdef CFG_16550_UART
static struct ns16550_data console_data __nex_bss;
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE, CORE_MMU_PGDIR_SIZE);
#endif

register_phys_mem_pgdir(MEM_AREA_IO_SEC, EFUSE_BANK7_BASE, CORE_MMU_PGDIR_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

/* HUK from the K1 factory eFuse die/chip IDs (bank 7, shadowed by U-Boot):
 * read-only (no fuse burned), per-device and non-zero, but not secret. */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(EFUSE_BANK7_BASE,
						EFUSE_BANK7_SIZE);
	uint32_t w[HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t)];
	unsigned int i;

	if (!base)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < ARRAY_SIZE(w); i++)
		w[i] = io_read32(base + EFUSE_HUK_OFFSET + i * sizeof(uint32_t));

	memcpy(hwkey->data, w, sizeof(hwkey->data));

	for (i = 0; i < ARRAY_SIZE(w); i++)
		if (w[i])
			return TEE_SUCCESS;

	/* All zero means the eFuse is unprogrammed/unreadable here. */
	EMSG("HUK: eFuse chip id reads all zero; storage is not device-bound");
	return TEE_SUCCESS;
}

#ifdef CFG_16550_UART
void plat_console_init(void)
{
	/* Polled output only: the UART (and its IER.UUE) stays set up by Linux/U-Boot */
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U32, UART0_REG_SHIFT);
	register_serial_console(&console_data.chip);
}
#endif

/* No secure interrupt sources yet: mask external interrupts instead of panicking. */
void interrupt_main_handler(void)
{
	clear_csr(CSR_XIE, CSR_XIE_EIE);
}
