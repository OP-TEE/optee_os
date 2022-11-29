// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <console.h>
#include <drivers/ns16550.h>
#include <kernel/tee_common_otp.h>
#include <kernel/huk_subkey.h>
#include <platform_config.h>

static struct ns16550_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, UART0_BASE,
			CORE_MMU_PGDIR_SIZE);

void console_init(void)
{
	ns16550_init(&console_data, UART0_BASE, IO_WIDTH_U8, 0);
	register_serial_console(&console_data.chip);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	memset(&hwkey->data[0], 0, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
