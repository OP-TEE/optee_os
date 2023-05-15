// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <arm.h>
#include <assert.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/sm.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

#define PLAT_HW_UNIQUE_KEY_LENGTH 32

static struct gic_data gic_data;
static struct serial8250_uart_data console_data;
static uint8_t plat_huk[PLAT_HW_UNIQUE_KEY_LENGTH];

register_phys_mem(MEM_AREA_RAM_SEC, TZDRAM_BASE, TEE_RAM_VA_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SECRAM_BASE, SECRAM_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GICC_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GICD_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  SERIAL8250_UART_REG_SIZE);

void main_init_gic(void)
{
	gic_init(&gic_data, GICC_BASE, GICD_BASE);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

struct plat_nsec_ctx {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t svc_spsr;
	uint32_t abt_sp;
	uint32_t abt_lr;
	uint32_t abt_spsr;
	uint32_t und_sp;
	uint32_t und_lr;
	uint32_t und_spsr;
	uint32_t irq_sp;
	uint32_t irq_lr;
	uint32_t irq_spsr;
	uint32_t fiq_sp;
	uint32_t fiq_lr;
	uint32_t fiq_spsr;
	uint32_t fiq_rx[5];
	uint32_t mon_lr;
	uint32_t mon_spsr;
};

struct plat_boot_args {
	struct plat_nsec_ctx nsec_ctx;
	uint8_t huk[PLAT_HW_UNIQUE_KEY_LENGTH];
};

void init_sec_mon(unsigned long nsec_entry)
{
	struct plat_boot_args *plat_boot_args;
	struct sm_nsec_ctx *nsec_ctx;

	plat_boot_args = phys_to_virt(nsec_entry, MEM_AREA_IO_SEC, 1);
	if (!plat_boot_args)
		panic();

	/* Invalidate cache to fetch data from external memory */
	cache_op_inner(DCACHE_AREA_INVALIDATE,
			plat_boot_args, sizeof(*plat_boot_args));

	/* Initialize secure monitor */
	nsec_ctx = sm_get_nsec_ctx();

	nsec_ctx->ub_regs.usr_sp = plat_boot_args->nsec_ctx.usr_sp;
	nsec_ctx->ub_regs.usr_lr = plat_boot_args->nsec_ctx.usr_lr;
	nsec_ctx->ub_regs.irq_spsr = plat_boot_args->nsec_ctx.irq_spsr;
	nsec_ctx->ub_regs.irq_sp = plat_boot_args->nsec_ctx.irq_sp;
	nsec_ctx->ub_regs.irq_lr = plat_boot_args->nsec_ctx.irq_lr;
	nsec_ctx->ub_regs.svc_spsr = plat_boot_args->nsec_ctx.svc_spsr;
	nsec_ctx->ub_regs.svc_sp = plat_boot_args->nsec_ctx.svc_sp;
	nsec_ctx->ub_regs.svc_lr = plat_boot_args->nsec_ctx.svc_lr;
	nsec_ctx->ub_regs.abt_spsr = plat_boot_args->nsec_ctx.abt_spsr;
	nsec_ctx->ub_regs.abt_sp = plat_boot_args->nsec_ctx.abt_sp;
	nsec_ctx->ub_regs.abt_lr = plat_boot_args->nsec_ctx.abt_lr;
	nsec_ctx->ub_regs.und_spsr = plat_boot_args->nsec_ctx.und_spsr;
	nsec_ctx->ub_regs.und_sp = plat_boot_args->nsec_ctx.und_sp;
	nsec_ctx->ub_regs.und_lr = plat_boot_args->nsec_ctx.und_lr;
	nsec_ctx->mon_lr = plat_boot_args->nsec_ctx.mon_lr;
	nsec_ctx->mon_spsr = plat_boot_args->nsec_ctx.mon_spsr;

	memcpy(plat_huk, plat_boot_args->huk, sizeof(plat_boot_args->huk));
}

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

#if defined(CFG_OTP_SUPPORT)

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	memcpy(&hwkey->data[0], &plat_huk[0], sizeof(hwkey->data));
	return TEE_SUCCESS;
}

#endif
