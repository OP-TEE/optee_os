// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2023, Linaro Limited
 * Copyright (c) 2014-2023, STMicroelectronics International N.V.
 * Copyright (C) 2022-2023 Nuvoton Ltd.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/ns16550.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

#define COLOR_NORMAL	"\x1B[0m"
#define COLOR_RED	"\x1B[31m"
#define COLOR_GREEN	"\x1B[32m"
#define COLOR_YELLOW	"\x1B[33m"
#define COLOR_BLUE	"\x1B[34m"
#define COLOR_MAGENTA	"\x1B[35m"
#define COLOR_CYAN	"\x1B[36m"
#define COLOR_WHITE	"\x1B[37m"

#define NPCM_MEASURE_BASE	0xF0848000
#define NPCM_MEASURE_UUID	0xC50
#define NPCM_MEASURE_SIZE	5

static struct ns16550_data console_data __nex_bss;

static struct {
	uint8_t data[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} npcm_hwkey;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, UART_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_RAM_NSEC, NPCM_MEASURE_BASE, SMALL_PAGE_SIZE);

register_ddr(DRAM0_BASE, DRAM0_SIZE);

static void print_version(void)
{
	IMSG(COLOR_MAGENTA);
	IMSG(">================================================");
	IMSG("OP-TEE OS Version %s", core_v_str);
	IMSG(">================================================");
	IMSG(COLOR_NORMAL);
}

void boot_primary_init_intc(void)
{
	if (IS_ENABLED(CFG_NPCM_DEBUG))
		print_version();

	gic_init(GICC_BASE, GICD_BASE);
}

void plat_console_init(void)
{
	ns16550_init(&console_data, CONSOLE_UART_BASE, IO_WIDTH_U32, 2);
	register_serial_console(&console_data.chip);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	void *vaddr = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t bin[HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t)] = {};
	uint8_t *bin_val = (uint8_t *)(&bin[0]);

	if (npcm_hwkey.ready)
		goto out;

	vaddr = phys_to_virt(NPCM_MEASURE_BASE + NPCM_MEASURE_UUID,
			     MEM_AREA_RAM_NSEC, NPCM_MEASURE_SIZE);
	if (!vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_SECURITY;
	}

	res = tee_hash_createdigest(TEE_ALG_SHA256, (uint8_t *)vaddr,
				    NPCM_MEASURE_SIZE, bin_val,
				    HW_UNIQUE_KEY_LENGTH);
	if (res != TEE_SUCCESS) {
		EMSG("Can't create a digest for HUK");
		return TEE_ERROR_SECURITY;
	}

	memcpy(&npcm_hwkey.data[0], bin, HW_UNIQUE_KEY_LENGTH);
	npcm_hwkey.ready = true;

	IMSG("HUK Initialized");

out:
	memcpy(hwkey->data, npcm_hwkey.data, HW_UNIQUE_KEY_LENGTH);

	return res;
}
