// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <console.h>
#include <crypto/crypto.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/tcc_otp.h>
#include <kernel/boot.h>
#include <kernel/tee_common_otp.h>
#include <otprom.h>
#include <platform_config.h>

register_phys_mem(MEM_AREA_IO_SEC, TCC_IO_BASE, TCC_IO_SIZE);
#if defined(TZC_BASE)
register_phys_mem(MEM_AREA_IO_SEC, TZC_BASE, TZC_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
#if defined(DRAM1_BASE)
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

static bool huk_is_ready;
static uint32_t plat_huk[OTP_DATA_TEE_HUK_SIZE / sizeof(uint32_t)];

void boot_primary_init_intc(void)
{
	gic_init(GICC_BASE, GICD_BASE);
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();
}

void plat_console_init(void)
{
#if defined(CFG_PL011)
	static struct pl011_data console_data;

	pl011_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_CLK_IN_HZ,
		   CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
#endif
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	static_assert(sizeof(plat_huk) == sizeof(hwkey->data));

	if (!huk_is_ready)
		return TEE_ERROR_GENERIC;

	memcpy(hwkey->data, plat_huk, OTP_DATA_TEE_HUK_SIZE);
	return TEE_SUCCESS;
}

static TEE_Result init_huk(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tcc_otp_read_128(OTP_DATA_TEE_HUK_OFFSET, plat_huk);
	if (res == TEE_ERROR_NO_DATA) {
		IMSG("There is no HUK in OTP. Starting HUK Provisioning");
		if (!crypto_rng_read(plat_huk, OTP_DATA_TEE_HUK_SIZE)) {
			tcc_otp_write_128(OTP_DATA_TEE_HUK_OFFSET, plat_huk);
			res = tcc_otp_read_128(OTP_DATA_TEE_HUK_OFFSET,
					       plat_huk);
			if (res != TEE_SUCCESS)
				EMSG("Failed to store HUK to OTP");
		} else {
			EMSG("Failed to generate random number for HUK");
		}
	}

	if (res == TEE_SUCCESS)
		huk_is_ready = true;
	else
		EMSG("Failed to get HUK from OTP");

	return res;
}
service_init(init_huk);
