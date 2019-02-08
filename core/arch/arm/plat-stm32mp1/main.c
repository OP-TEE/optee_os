// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32_uart.h>
#include <drivers/stm32mp1_etzpc.h>
#include <kernel/generic_boot.h>
#include <kernel/dt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stm32_util.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <trace.h>

#ifdef CFG_WITH_NSEC_UARTS
register_phys_mem(MEM_AREA_IO_NSEC, USART1_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, USART2_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, USART3_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART4_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART5_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, USART6_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART7_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART8_BASE, SMALL_PAGE_SIZE);
#endif

register_phys_mem(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, RCC_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PWR_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, TAMP_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, USART1_BASE, SMALL_PAGE_SIZE);

static void main_fiq(void);

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

#define _ID2STR(id)		(#id)
#define ID2STR(id)		_ID2STR(id)

static TEE_Result platform_banner(void)
{
#ifdef CFG_EMBED_DTB
	IMSG("Platform stm32mp1: flavor %s - DT %s",
		ID2STR(PLATFORM_FLAVOR),
		ID2STR(CFG_EMBED_DTB_SOURCE_FILE));
#else
	IMSG("Platform stm32mp1: flavor %s - no device tree",
		ID2STR(PLATFORM_FLAVOR));
#endif

	return TEE_SUCCESS;
}
service_init(platform_banner);

/*
 * Console
 *
 * CFG_STM32_EARLY_CONSOLE_UART specifies the ID of the UART used for
 * trace console. Value 0 disables the early console.
 *
 * We cannot use the generic serial_console support since probing
 * the console requires the platform clock driver to be already
 * up and ready which is done only once service_init are completed.
 */
static struct stm32_uart_pdata console_data;

void console_init(void)
{
	/* Early console initialization before MMU setup */
	struct uart {
		uintptr_t pa;
		bool secure;
	} uarts[] = {
		[0] = { .pa = 0 },
		[1] = { .pa = USART1_BASE, .secure = true, },
		[2] = { .pa = USART2_BASE, .secure = false, },
		[3] = { .pa = USART3_BASE, .secure = false, },
		[4] = { .pa = UART4_BASE, .secure = false, },
		[5] = { .pa = UART5_BASE, .secure = false, },
		[6] = { .pa = USART6_BASE, .secure = false, },
		[7] = { .pa = UART7_BASE, .secure = false, },
		[8] = { .pa = UART8_BASE, .secure = false, },
	};

	COMPILE_TIME_ASSERT(ARRAY_SIZE(uarts) > CFG_STM32_EARLY_CONSOLE_UART);
	assert(!cpu_mmu_enabled());

	if (!uarts[CFG_STM32_EARLY_CONSOLE_UART].pa)
		return;

	/* No clock yet bound to the UART console */
	console_data.clock = DT_INFO_INVALID_CLOCK;

	console_data.secure = uarts[CFG_STM32_EARLY_CONSOLE_UART].secure;
	stm32_uart_init(&console_data, uarts[CFG_STM32_EARLY_CONSOLE_UART].pa);

	register_serial_console(&console_data.chip);

	IMSG("Early console on UART#%u", CFG_STM32_EARLY_CONSOLE_UART);
}

#ifdef CFG_DT
static TEE_Result init_console_from_dt(void)
{
	struct stm32_uart_pdata *pd;
	void *fdt;
	int node;

	if (get_console_node_from_dt(&fdt, &node, NULL, NULL))
		return TEE_SUCCESS;

	pd = stm32_uart_init_from_dt_node(fdt, node);
	if (!pd) {
		IMSG("DTB disables console");
		register_serial_console(NULL);
		return TEE_SUCCESS;
	}

	/* Replace early console with the new one */
	console_flush();
	console_data = *pd;
	free(pd);
	register_serial_console(&console_data.chip);
	IMSG("DTB enables console (%ssecure)", pd->secure ? "" : "non-");

	return TEE_SUCCESS;
}

/* Probe console from DT once clock inits (service init level) are completed */
service_init_late(init_console_from_dt);
#endif

/*
 * GIC init, used also for primary/secondary boot core wake completion
 */
static struct gic_data gic_data;

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void main_init_gic(void)
{
	assert(cpu_mmu_enabled());

	gic_init(&gic_data, get_gicc_base(), get_gicd_base());
	itr_init(&gic_data.chip);

	stm32mp_register_online_cpu();
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);

	stm32mp_register_online_cpu();
}

#ifndef CFG_EMBED_DTB
static TEE_Result init_stm32mp1_drivers(void)
{
	/* Without secure DTB support, some drivers must be inited */
	stm32_etzpc_init(ETZPC_BASE);

	return TEE_SUCCESS;
}
driver_init(init_stm32mp1_drivers);
#endif /*!CFG_EMBED_DTB*/

/* Platform initializations once all drivers are ready */
static TEE_Result init_late_stm32mp1_drivers(void)
{
	/* Secure internal memories for the platform, once ETZPC is ready */
	etzpc_configure_tzma(0, ETZPC_TZMA_ALL_SECURE);
	etzpc_lock_tzma(0);
	etzpc_configure_tzma(1, ETZPC_TZMA_ALL_SECURE);
	etzpc_lock_tzma(1);

	/* Static secure DECPROT configuration */
	etzpc_configure_decprot(STM32MP1_ETZPC_STGENC_ID, ETZPC_DECPROT_S_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_BKPSRAM_ID, ETZPC_DECPROT_S_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_IWDG1_ID, ETZPC_DECPROT_S_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_DDRCTRL_ID, ETZPC_DECPROT_S_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_DDRPHYC_ID, ETZPC_DECPROT_S_RW);
	etzpc_lock_decprot(STM32MP1_ETZPC_STGENC_ID);
	etzpc_lock_decprot(STM32MP1_ETZPC_BKPSRAM_ID);
	etzpc_lock_decprot(STM32MP1_ETZPC_IWDG1_ID);
	etzpc_lock_decprot(STM32MP1_ETZPC_DDRCTRL_ID);
	etzpc_lock_decprot(STM32MP1_ETZPC_DDRPHYC_ID);
	/* Static non-secure DECPROT configuration */
	etzpc_configure_decprot(STM32MP1_ETZPC_I2C4_ID, ETZPC_DECPROT_NS_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_RNG1_ID, ETZPC_DECPROT_NS_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_HASH1_ID, ETZPC_DECPROT_NS_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_CRYP1_ID, ETZPC_DECPROT_NS_RW);
	/* Release few resource to the non-secure world */
	etzpc_configure_decprot(STM32MP1_ETZPC_USART1_ID, ETZPC_DECPROT_NS_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_SPI6_ID, ETZPC_DECPROT_NS_RW);
	etzpc_configure_decprot(STM32MP1_ETZPC_I2C6_ID, ETZPC_DECPROT_NS_RW);

	return TEE_SUCCESS;
}
driver_init_late(init_late_stm32mp1_drivers);

uintptr_t get_gicc_base(void)
{
	uintptr_t pbase = GIC_BASE + GICC_OFFSET;

	if (cpu_mmu_enabled())
		return (uintptr_t)phys_to_virt_io(pbase);

	return pbase;
}

uintptr_t get_gicd_base(void)
{
	uintptr_t pbase = GIC_BASE + GICD_OFFSET;

	if (cpu_mmu_enabled())
		return (uintptr_t)phys_to_virt_io(pbase);

	return pbase;
}

uint32_t may_spin_lock(unsigned int *lock)
{
	if (!lock || !cpu_mmu_enabled())
		return 0;

	return cpu_spin_lock_xsave(lock);
}

void may_spin_unlock(unsigned int *lock, uint32_t exceptions)
{
	if (!lock || !cpu_mmu_enabled())
		return;

	cpu_spin_unlock_xrestore(lock, exceptions);
}

static uintptr_t stm32_tamp_base(void)
{
	static struct io_pa_va base = { .pa = TAMP_BASE };

	return io_pa_or_va(&base);
}

static uintptr_t bkpreg_base(void)
{
	return stm32_tamp_base() + TAMP_BKP_REGISTER_OFF;
}

uintptr_t stm32mp_bkpreg(unsigned int idx)
{
	return bkpreg_base() + (idx * sizeof(uint32_t));
}
