// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#include <console.h>
#include <kernel/boot.h>
#include <kernel/tee_common_otp.h>
#include <drivers/gic.h>
#include <drivers/pl011.h>
#include <drivers/tcc_otp.h>
#include <crypto/crypto.h>
#include <platform_config.h>
#include <otprom.h>

register_phys_mem(MEM_AREA_IO_SEC, TCC_IO_BASE, TCC_IO_SIZE);
#if defined(TZC_BASE)
register_phys_mem(MEM_AREA_IO_SEC, TZC_BASE, TZC_SIZE);
#endif

register_ddr(DRAM0_BASE, DRAM0_SIZE);
#if defined(DRAM1_BASE)
register_ddr(DRAM1_BASE, DRAM1_SIZE);
#endif

static bool is_huk_ready;
static uint32_t plat_huk[OTP_DATA_TEE_HUK_SIZE / 4U] = { 0 };

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
	TEE_Result res = TEE_ERROR_GENERIC;

	(void)memset(&hwkey->data[0], 0x0, sizeof(hwkey->data));
	if (is_huk_ready) {
		(void)memcpy(&hwkey->data[0], &plat_huk[0],
			     OTP_DATA_TEE_HUK_SIZE);
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result huk_ready(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tcc_otp_read_128(OTP_DATA_TEE_HUK_OFFSET, plat_huk);
	if (res == TEE_ERROR_NO_DATA) {
		IMSG("There is no HUK in OTP. Starting HUK Provisioning");
		if (crypto_rng_read(plat_huk, OTP_DATA_TEE_HUK_SIZE)
			== TEE_SUCCESS) {
			(void)tcc_otp_write_128(OTP_DATA_TEE_HUK_OFFSET,
						plat_huk);
			res = tcc_otp_read_128(OTP_DATA_TEE_HUK_OFFSET,
					       plat_huk);
			if (res != TEE_SUCCESS)
				EMSG("Failed to store HUK to OTP");
		} else {
			EMSG("Failed to generate random number for HUK");
		}
	}

	if (res == TEE_SUCCESS)
		is_huk_ready = true;
	else
		EMSG("Failed to get HUK from OTP");

	return res;
}
service_init(huk_ready);
