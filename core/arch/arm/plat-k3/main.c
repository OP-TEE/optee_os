// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016-2018 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <drivers/ti_sci.h>
#include <drivers/ti_sci_transport.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <stdint.h>
#include <string_ext.h>

static struct serial8250_uart_data console_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GICC_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GICD_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  SERIAL8250_UART_REG_SIZE);
#if defined(PLATFORM_FLAVOR_am62lx)
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TI_MAILBOX_TX_BASE, 0x1000);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TI_MAILBOX_RX_BASE, 0x1000);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, MAILBOX_TX_START_REGION, 0x1000);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, MAILBOX_RX_START_REGION, 0x1000);
#else
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SEC_PROXY_DATA_BASE,
			SEC_PROXY_DATA_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SEC_PROXY_SCFG_BASE,
			SEC_PROXY_SCFG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SEC_PROXY_RT_BASE, SEC_PROXY_RT_SIZE);
#endif
register_ddr(DRAM0_BASE, DRAM0_SIZE);
register_ddr(DRAM1_BASE, DRAM1_SIZE);

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
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

static TEE_Result init_ti_sci(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = ti_sci_transport_init();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = ti_sci_init();
	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

/*
 * TISCI services are required for initialization of TRNG service that gets
 * initialized during service_init_crypto.
 *
 * Initialize TISCI service just before service_init_crypto.
 */
early_init_late(init_ti_sci);

static TEE_Result secure_boot_information(void)
{
	uint32_t keycnt = 0;
	uint32_t keyrev = 0;
	uint32_t swrev = 0;

	if (!ti_sci_get_swrev(&swrev))
		IMSG("Secure Board Configuration Software: Rev %"PRIu32,
		     swrev);

	if (!ti_sci_get_keycnt_keyrev(&keycnt, &keyrev))
		IMSG("Secure Boot Keys: Count %"PRIu32 ", Rev %"PRIu32,
		     keycnt, keyrev);

	return TEE_SUCCESS;
}

service_init_late(secure_boot_information);

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint8_t dkek[SA2UL_DKEK_KEY_LEN] = { };
	int ret = 0;

	assert(SA2UL_DKEK_KEY_LEN >= HW_UNIQUE_KEY_LENGTH);

	ret = ti_sci_get_dkek(0, "OP-TEE", "DKEK", dkek);
	if (ret) {
		EMSG("Could not get HUK");
		return TEE_ERROR_SECURITY;
	}

	memcpy(&hwkey->data[0], dkek, sizeof(hwkey->data));
	memzero_explicit(&dkek, sizeof(dkek));

	IMSG("HUK Initialized");

	return TEE_SUCCESS;
}
