// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <config.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32mp1_etzpc.h>
#include <drivers/stm32_uart.h>
#include <dt-bindings/clock/stm32mp1-clks.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stm32_util.h>
#include <trace.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB1_BASE, APB1_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB2_BASE, APB2_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB3_BASE, APB3_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB4_BASE, APB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB5_BASE, APB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AHB4_BASE, AHB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AHB5_BASE, AHB5_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB3_BASE, APB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB5_BASE, APB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB4_BASE, AHB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB5_BASE, AHB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);

register_ddr(DDR_BASE, CFG_DRAM_SIZE);

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
		paddr_t pa;
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

	if (!uarts[CFG_STM32_EARLY_CONSOLE_UART].pa)
		return;

	/* No clock yet bound to the UART console */
	console_data.clock = DT_INFO_INVALID_CLOCK;

	console_data.secure = uarts[CFG_STM32_EARLY_CONSOLE_UART].secure;
	stm32_uart_init(&console_data, uarts[CFG_STM32_EARLY_CONSOLE_UART].pa);

	register_serial_console(&console_data.chip);

	IMSG("Early console on UART#%u", CFG_STM32_EARLY_CONSOLE_UART);
}

#ifdef CFG_EMBED_DTB
static TEE_Result init_console_from_dt(void)
{
	struct stm32_uart_pdata *pd = NULL;
	void *fdt = NULL;
	int node = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	fdt = get_embedded_dt();
	res = get_console_node_from_dt(fdt, &node, NULL, NULL);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		fdt = get_external_dt();
		res = get_console_node_from_dt(fdt, &node, NULL, NULL);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_SUCCESS;
		if (res != TEE_SUCCESS)
			return res;
	}

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

void itr_core_handler(void)
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

static TEE_Result init_stm32mp1_drivers(void)
{
	/* Without secure DTB support, some drivers must be inited */
	if (!IS_ENABLED(CFG_EMBED_DTB))
		stm32_etzpc_init(ETZPC_BASE);

	/* Secure internal memories for the platform, once ETZPC is ready */
	etzpc_configure_tzma(0, ETZPC_TZMA_ALL_SECURE);
	etzpc_lock_tzma(0);

	COMPILE_TIME_ASSERT(((SYSRAM_BASE + SYSRAM_SIZE) <= CFG_TZSRAM_START) ||
			    ((SYSRAM_BASE <= CFG_TZSRAM_START) &&
			     (SYSRAM_SEC_SIZE >= CFG_TZSRAM_SIZE)));

	etzpc_configure_tzma(1, SYSRAM_SEC_SIZE >> SMALL_PAGE_SHIFT);
	etzpc_lock_tzma(1);

	return TEE_SUCCESS;
}
service_init_late(init_stm32mp1_drivers);

vaddr_t get_gicc_base(void)
{
	struct io_pa_va base = { .pa = GIC_BASE + GICC_OFFSET };

	return io_pa_or_va_secure(&base, 1);
}

vaddr_t get_gicd_base(void)
{
	struct io_pa_va base = { .pa = GIC_BASE + GICD_OFFSET };

	return io_pa_or_va_secure(&base, 1);
}

void stm32mp_get_bsec_static_cfg(struct stm32_bsec_static_cfg *cfg)
{
	cfg->base = BSEC_BASE;
	cfg->upper_start = STM32MP1_UPPER_OTP_START;
	cfg->max_id = STM32MP1_OTP_MAX_ID;
}

bool stm32mp_is_closed_device(void)
{
	uint32_t otp = 0;
	TEE_Result result = TEE_ERROR_GENERIC;

	/* Non closed_device platform expects fuse well programmed to 0 */
	result = stm32_bsec_shadow_read_otp(&otp, DATA0_OTP);
	if (!result && !(otp & BIT(DATA0_OTP_SECURED_POS)))
		return false;

	return true;
}

bool __weak stm32mp_with_pmic(void)
{
	return false;
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

static vaddr_t stm32_tamp_base(void)
{
	static struct io_pa_va base = { .pa = TAMP_BASE };

	return io_pa_or_va_secure(&base, 1);
}

static vaddr_t bkpreg_base(void)
{
	return stm32_tamp_base() + TAMP_BKP_REGISTER_OFF;
}

vaddr_t stm32mp_bkpreg(unsigned int idx)
{
	return bkpreg_base() + (idx * sizeof(uint32_t));
}

#ifdef CFG_STM32_GPIO
vaddr_t stm32_get_gpio_bank_base(unsigned int bank)
{
	static struct io_pa_va gpios_nsec_base = { .pa = GPIOS_NSEC_BASE };
	static struct io_pa_va gpioz_base = { .pa = GPIOZ_BASE };

	/* Get secure mapping address for GPIOZ */
	if (bank == GPIO_BANK_Z)
		return io_pa_or_va_secure(&gpioz_base, GPIO_BANK_OFFSET);

	COMPILE_TIME_ASSERT(GPIO_BANK_A == 0);
	assert(bank <= GPIO_BANK_K);

	return io_pa_or_va_nsec(&gpios_nsec_base,
				(bank + 1) * GPIO_BANK_OFFSET) +
		(bank * GPIO_BANK_OFFSET);
}

unsigned int stm32_get_gpio_bank_offset(unsigned int bank)
{
	if (bank == GPIO_BANK_Z)
		return 0;

	assert(bank <= GPIO_BANK_K);
	return bank * GPIO_BANK_OFFSET;
}

unsigned int stm32_get_gpio_bank_clock(unsigned int bank)
{
	if (bank == GPIO_BANK_Z)
		return GPIOZ;

	assert(bank <= GPIO_BANK_K);
	return GPIOA + bank;
}
#endif /* CFG_STM32_GPIO */
