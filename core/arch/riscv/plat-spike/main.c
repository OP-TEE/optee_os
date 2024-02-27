// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <console.h>
#include <kernel/tee_common_otp.h>
#include <kernel/huk_subkey.h>
#include <platform_config.h>

#include "drivers/htif.h"

#ifdef CFG_RISCV_M_MODE
static struct htif_console_data console_data __nex_bss;

void plat_console_init(void)
{
#ifdef HTIF_BASE
	htif_console_init(&console_data, HTIF_BASE);
	register_serial_console(&console_data.chip);
#endif /*HTIF_BASE*/
}
#endif /*CFG_RISCV_M_MODE*/

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	memset(&hwkey->data[0], 0, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
