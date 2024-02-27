// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2022, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <config.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32_iwdg.h>
#include <drivers/stm32_tamp.h>
#include <drivers/stm32_uart.h>
#include <drivers/stm32mp1_etzpc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stm32_util.h>
#include <string.h>
#include <trace.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB1_BASE, APB1_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB2_BASE, APB2_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB3_BASE, APB3_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB4_BASE, APB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, APB5_BASE, APB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AHB4_BASE, AHB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AHB5_BASE, AHB5_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB1_BASE, APB1_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB3_BASE, APB3_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB4_BASE, APB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB5_BASE, APB5_SIZE);
#ifdef CFG_STM32MP13
register_phys_mem_pgdir(MEM_AREA_IO_SEC, APB6_BASE, APB6_SIZE);
#endif
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB4_BASE, AHB4_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, AHB5_BASE, AHB5_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE, GIC_SIZE);

register_ddr(DDR_BASE, CFG_DRAM_SIZE);

#define _ID2STR(id)		(#id)
#define ID2STR(id)		_ID2STR(id)

static TEE_Result platform_banner(void)
{
	IMSG("Platform stm32mp1: flavor %s - DT %s",
		ID2STR(PLATFORM_FLAVOR),
		ID2STR(CFG_EMBED_DTB_SOURCE_FILE));

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

void plat_console_init(void)
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
	console_data.clock = NULL;

	console_data.secure = uarts[CFG_STM32_EARLY_CONSOLE_UART].secure;
	stm32_uart_init(&console_data, uarts[CFG_STM32_EARLY_CONSOLE_UART].pa);

	register_serial_console(&console_data.chip);

	IMSG("Early console on UART#%u", CFG_STM32_EARLY_CONSOLE_UART);
}

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
	register_serial_console(&console_data.chip);
	IMSG("DTB enables console (%ssecure)", pd->secure ? "" : "non-");
	free(pd);

	return TEE_SUCCESS;
}

/* Probe console from DT once clock inits (service init level) are completed */
service_init_late(init_console_from_dt);

/*
 * GIC init, used also for primary/secondary boot core wake completion
 */
void boot_primary_init_intc(void)
{
	gic_init(GIC_BASE + GICC_OFFSET, GIC_BASE + GICD_OFFSET);

	stm32mp_register_online_cpu();
}

void boot_secondary_init_intc(void)
{
	gic_init_per_cpu();

	stm32mp_register_online_cpu();
}

#ifdef CFG_STM32MP13
#ifdef CFG_STM32_ETZPC
/* Configure ETZPC cell and lock it when resource is secure */
static void config_lock_decprot(uint32_t decprot_id,
				enum etzpc_decprot_attributes decprot_attr)
{
	etzpc_configure_decprot(decprot_id, decprot_attr);

	if (decprot_attr == ETZPC_DECPROT_S_RW)
		etzpc_lock_decprot(decprot_id);
}

static TEE_Result set_etzpc_secure_configuration(void)
{
	config_lock_decprot(STM32MP1_ETZPC_BKPSRAM_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_DDRCTRLPHY_ID,
			    ETZPC_DECPROT_NS_R_S_W);

	/* Configure ETZPC with peripheral registering */
	config_lock_decprot(STM32MP1_ETZPC_ADC1_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_ADC2_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_CRYP_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_DCMIPP_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_ETH1_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_ETH2_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_FMC_ID, ETZPC_DECPROT_NS_RW);
	/* HASH is secure */
	config_lock_decprot(STM32MP1_ETZPC_HASH_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_I2C3_ID, ETZPC_DECPROT_NS_RW);
	/* I2C4 is secure */
	config_lock_decprot(STM32MP1_ETZPC_I2C4_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_I2C5_ID, ETZPC_DECPROT_NS_RW);
	/* IWDG1 is secure */
	config_lock_decprot(STM32MP1_ETZPC_IWDG1_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_LPTIM2_ID, ETZPC_DECPROT_NS_RW);
	/* LPTIM3 is secure */
	config_lock_decprot(STM32MP1_ETZPC_LPTIM3_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_LTDC_ID, ETZPC_DECPROT_NS_RW);
	/* MCE is secure */
	config_lock_decprot(STM32MP1_ETZPC_MCE_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_OTG_ID, ETZPC_DECPROT_NS_RW);
	/* PKA is secure */
	config_lock_decprot(STM32MP1_ETZPC_PKA_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_QSPI_ID, ETZPC_DECPROT_NS_RW);
	/* RNG is secure */
	config_lock_decprot(STM32MP1_ETZPC_RNG_ID, ETZPC_DECPROT_S_RW);
	/* SAES is secure */
	config_lock_decprot(STM32MP1_ETZPC_SAES_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_SDMMC1_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_SDMMC2_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_SPI4_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_SPI5_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_SRAM1_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_SRAM2_ID, ETZPC_DECPROT_NS_RW);
	/* SRAM3 is secure */
	config_lock_decprot(STM32MP1_ETZPC_SRAM3_ID, ETZPC_DECPROT_S_RW);
	/* STGENC is secure */
	config_lock_decprot(STM32MP1_ETZPC_STGENC_ID, ETZPC_DECPROT_S_RW);
	/* TIM12 is secure */
	config_lock_decprot(STM32MP1_ETZPC_TIM12_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_TIM13_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_TIM14_ID, ETZPC_DECPROT_NS_RW);
	/* TIM15 is secure */
	config_lock_decprot(STM32MP1_ETZPC_TIM15_ID, ETZPC_DECPROT_S_RW);
	config_lock_decprot(STM32MP1_ETZPC_TIM16_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_TIM17_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_USART1_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_USART2_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_USBPHYCTRL_ID, ETZPC_DECPROT_NS_RW);
	config_lock_decprot(STM32MP1_ETZPC_VREFBUF_ID, ETZPC_DECPROT_NS_RW);

	return TEE_SUCCESS;
}

driver_init_late(set_etzpc_secure_configuration);
#endif /* CFG_STM32_ETZPC */
#endif /* CFG_STM32MP13 */

#ifdef CFG_STM32MP15
/*
 * This concerns OP-TEE pager for STM32MP1 to use secure internal
 * RAMs to execute. TZSRAM refers the TZSRAM_BASE/TZSRAM_SIZE
 * used in boot.c to locate secure unpaged memory.
 *
 * STM32MP15 variants embed 640kB of contiguous securable SRAMs
 *
 *  +--------------+ <-- SYSRAM_BASE
 *  |              |     lower part can be assigned to secure world
 *  | SYSRAM 256kB |     4kB granule boundary
 *  |              |     upper part can be assigned to secure world
 *  +--------------+ <-- SRAM1_BASE (= SYSRAM_BASE + SYSRAM_SIZE)
    |              |     full range assigned to non-secure world or
 *  | SRAM1  128kB |     to secure world, or to- Cortex-M4 exclusive access
 *  +--------------+ <-- SRAM2_BASE (= SRAM1_BASE + SRAM1_SIZE)
    |              |     full range assigned to non-secure world or
 *  | SRAM2  128kB |     to secure world, or to- Cortex-M4 exclusive access
 *  +--------------+ <-- SRAM3_BASE (= SRAM2_BASE + SRAM2_SIZE)
    |              |     full range assigned to non-secure world or
 *  | SRAM3   64kB |     to secure world, or to- Cortex-M4 exclusive access
 *  +--------------+ <-- SRAM4_BASE (= SRAM3_BASE + SRAM3_SIZE)
    |              |     full range assigned to non-secure world or
 *  | SRAM4   64kB |     to secure world, or to- Cortex-M4 exclusive access
 *  +--------------+ <-- SRAM4_BASE + SRAM4_SIZE
 *
 * If SRAMx memories are not used for the companion Cortex-M4
 * processor, OP-TEE can use this memory.
 *
 * SYSRAM configuration for secure/non-secure boundaries requires the
 * secure SYSRAM memory to start at the SYSRAM physical base address and grow
 * from there while the non-secure SYSRAM range lies at SYSRAM end addresses
 * with a 4KB page granule.
 *
 * SRAM1, SRAM2, SRAM3 and SRAM4 are independently assigned to secure world,
 * to non-secure world or possibly to Cortex-M4 exclusive access. Each
 * assignment covers the full related SRAMx memory range.
 *
 * Using non-secure SYSRAM or one of the SRAMx for SCMI message communication
 * can be done using CFG_STM32MP1_SCMI_SHM_BASE/CFG_STM32MP1_SCMI_SHM_SIZE.
 * This imposes related memory area is assigned to non-secure world.

 * Using secure internal memories (SYSRAM and/or some SRAMx) with STM32MP15
 * shall meet this constraints known the TZSRAM physical memory range shall
 * be contiguous.
 */

#define SYSRAM_END			(SYSRAM_BASE + SYSRAM_SIZE)
#define SYSRAM_SEC_END			(SYSRAM_BASE + SYSRAM_SEC_SIZE)
#define SRAMS_END			(SRAM4_BASE + SRAM4_SIZE)
#define SRAMS_START			SRAM1_BASE
#define TZSRAM_END			(CFG_TZSRAM_START + CFG_TZSRAM_SIZE)

#define SCMI_SHM_IS_IN_SRAMX	((CFG_STM32MP1_SCMI_SHM_BASE >= SRAM1_BASE) && \
				 (CFG_STM32MP1_SCMI_SHM_BASE + \
				  CFG_STM32MP1_SCMI_SHM_SIZE) <= SRAMS_END)

#define TZSRAM_FITS_IN_SYSRAM_SEC	((CFG_TZSRAM_START >= SYSRAM_BASE) && \
					 (TZSRAM_END <= SYSRAM_SEC_END))

#define TZSRAM_FITS_IN_SYSRAM_AND_SRAMS	((CFG_TZSRAM_START >= SYSRAM_BASE) && \
					 (CFG_TZSRAM_START < SYSRAM_END) && \
					 (TZSRAM_END > SYSRAM_END) && \
					 (TZSRAM_END <= SRAMS_END) && \
					 (SYSRAM_SIZE == SYSRAM_SEC_SIZE))

#define TZSRAM_FITS_IN_SRAMS	((CFG_TZSRAM_START >= SRAMS_START) && \
				 (CFG_TZSRAM_START < SRAMS_END) && \
				 (TZSRAM_END <= SRAMS_END))

#define TZSRAM_IS_IN_DRAM	(CFG_TZSRAM_START >= CFG_DRAM_BASE)

#ifdef CFG_WITH_PAGER
/*
 * At build time, we enforce that, when pager is used,
 * either TZSRAM fully fits inside SYSRAM secure address range,
 * or TZSRAM fully fits inside the full SYSRAM and spread inside SRAMx orderly,
 * or TZSRAM fully fits some inside SRAMs address range,
 * or TZSRAM is in DDR for debug and test purpose.
 */
static_assert(TZSRAM_FITS_IN_SYSRAM_SEC || TZSRAM_FITS_IN_SYSRAM_AND_SRAMS ||
	      TZSRAM_FITS_IN_SRAMS || TZSRAM_IS_IN_DRAM);
#endif

#if TZSRAM_FITS_IN_SYSRAM_AND_SRAMS || TZSRAM_FITS_IN_SRAMS || \
	SCMI_SHM_IS_IN_SRAMX
/* At run time we enforce that SRAM1 to SRAM4 are properly assigned if used */
static TEE_Result init_stm32mp15_secure_srams(void)
{
	if (IS_ENABLED(CFG_WITH_PAGER)) {
		if (core_is_buffer_intersect(CFG_TZSRAM_START, CFG_TZSRAM_SIZE,
					     SRAM1_BASE, SRAM1_SIZE))
			stm32mp_register_secure_periph_iomem(SRAM1_BASE);

		if (core_is_buffer_intersect(CFG_TZSRAM_START, CFG_TZSRAM_SIZE,
					     SRAM2_BASE, SRAM2_SIZE))
			stm32mp_register_secure_periph_iomem(SRAM2_BASE);

		if (core_is_buffer_intersect(CFG_TZSRAM_START, CFG_TZSRAM_SIZE,
					     SRAM3_BASE, SRAM3_SIZE))
			stm32mp_register_secure_periph_iomem(SRAM3_BASE);

		if (core_is_buffer_intersect(CFG_TZSRAM_START, CFG_TZSRAM_SIZE,
					     SRAM4_BASE, SRAM4_SIZE))
			stm32mp_register_secure_periph_iomem(SRAM4_BASE);
	}

	if (SCMI_SHM_IS_IN_SRAMX) {
		if (core_is_buffer_intersect(CFG_STM32MP1_SCMI_SHM_BASE,
					     CFG_STM32MP1_SCMI_SHM_SIZE,
					     SRAM1_BASE, SRAM1_SIZE))
			stm32mp_register_non_secure_periph_iomem(SRAM1_BASE);

		if (core_is_buffer_intersect(CFG_STM32MP1_SCMI_SHM_BASE,
					     CFG_STM32MP1_SCMI_SHM_SIZE,
					     SRAM2_BASE, SRAM2_SIZE))
			stm32mp_register_non_secure_periph_iomem(SRAM2_BASE);

		if (core_is_buffer_intersect(CFG_STM32MP1_SCMI_SHM_BASE,
					     CFG_STM32MP1_SCMI_SHM_SIZE,
					     SRAM3_BASE, SRAM3_SIZE))
			stm32mp_register_non_secure_periph_iomem(SRAM3_BASE);

		if (core_is_buffer_intersect(CFG_STM32MP1_SCMI_SHM_BASE,
					     CFG_STM32MP1_SCMI_SHM_SIZE,
					     SRAM4_BASE, SRAM4_SIZE))
			stm32mp_register_non_secure_periph_iomem(SRAM4_BASE);
	}

	return TEE_SUCCESS;
}

service_init_late(init_stm32mp15_secure_srams);
#endif /* TZSRAM_FITS_IN_SYSRAM_AND_SRAMS || TZSRAM_FITS_IN_SRAMS */
#endif /* CFG_STM32MP15 && CFG_TZSRAM_START */

static TEE_Result init_stm32mp1_drivers(void)
{
	/* Secure internal memories for the platform, once ETZPC is ready */
	etzpc_configure_tzma(0, ETZPC_TZMA_ALL_SECURE);
	etzpc_lock_tzma(0);

	etzpc_configure_tzma(1, SYSRAM_SEC_SIZE >> SMALL_PAGE_SHIFT);
	etzpc_lock_tzma(1);

	if (SYSRAM_SIZE > SYSRAM_SEC_SIZE) {
		size_t nsec_size = SYSRAM_SIZE - SYSRAM_SEC_SIZE;
		paddr_t nsec_start = SYSRAM_BASE + SYSRAM_SEC_SIZE;
		uint8_t *va = phys_to_virt(nsec_start, MEM_AREA_IO_NSEC,
					   nsec_size);

		IMSG("Non-secure SYSRAM [%p %p]", va, va + nsec_size - 1);

		/* Clear content from the non-secure part */
		memset(va, 0, nsec_size);
	}

	return TEE_SUCCESS;
}

service_init_late(init_stm32mp1_drivers);

static TEE_Result init_late_stm32mp1_drivers(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Set access permission to TAM backup registers */
	if (IS_ENABLED(CFG_STM32_TAMP)) {
		struct stm32_bkpregs_conf conf = {
			.nb_zone1_regs = TAMP_BKP_REGISTER_ZONE1_COUNT,
			.nb_zone2_regs = TAMP_BKP_REGISTER_ZONE2_COUNT,
		};

		res = stm32_tamp_set_secure_bkpregs(&conf);
		if (res == TEE_ERROR_DEFER_DRIVER_INIT) {
			/* TAMP driver was not probed if disabled in the DT */
			res = TEE_SUCCESS;
		}
		if (res)
			panic();
	}

	return TEE_SUCCESS;
}

driver_init_late(init_late_stm32mp1_drivers);

vaddr_t stm32_rcc_base(void)
{
	static struct io_pa_va base = { .pa = RCC_BASE };

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

static bool __maybe_unused bank_is_valid(unsigned int bank)
{
	if (IS_ENABLED(CFG_STM32MP15))
		return bank == GPIO_BANK_Z || bank <= GPIO_BANK_K;

	if (IS_ENABLED(CFG_STM32MP13))
		return bank <= GPIO_BANK_I;

	panic();
}

#ifdef CFG_STM32_IWDG
TEE_Result stm32_get_iwdg_otp_config(paddr_t pbase,
				     struct stm32_iwdg_otp_data *otp_data)
{
	unsigned int idx = 0;
	uint32_t otp_id = 0;
	size_t bit_len = 0;
	uint8_t bit_offset = 0;
	uint32_t otp_value = 0;

	switch (pbase) {
	case IWDG1_BASE:
		idx = 0;
		break;
	case IWDG2_BASE:
		idx = 1;
		break;
	default:
		panic();
	}

	if (stm32_bsec_find_otp_in_nvmem_layout("hw2_otp", &otp_id, &bit_offset,
						&bit_len) ||
	    bit_len != 32 || bit_offset != 0)
		panic();

	if (stm32_bsec_read_otp(&otp_value, otp_id))
		panic();

	otp_data->hw_enabled = otp_value &
			       BIT(idx + HW2_OTP_IWDG_HW_ENABLE_SHIFT);
	otp_data->disable_on_stop = otp_value &
				    BIT(idx + HW2_OTP_IWDG_FZ_STOP_SHIFT);
	otp_data->disable_on_standby = otp_value &
				       BIT(idx + HW2_OTP_IWDG_FZ_STANDBY_SHIFT);

	return TEE_SUCCESS;
}
#endif /*CFG_STM32_IWDG*/

#ifdef CFG_STM32_DEBUG_ACCESS
static TEE_Result init_debug(void)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t conf = stm32_bsec_read_debug_conf();
	struct clk *dbg_clk = stm32mp_rcc_clock_id_to_clk(CK_DBG);
	uint32_t state = 0;

	res = stm32_bsec_get_state(&state);
	if (res)
		return res;

	if (state != BSEC_STATE_SEC_CLOSED && conf) {
		if (IS_ENABLED(CFG_INSECURE))
			IMSG("WARNING: All debug accesses are allowed");

		res = stm32_bsec_write_debug_conf(conf | BSEC_DEBUG_ALL);
		if (res)
			return res;

		/*
		 * Enable DBG clock as used to access coprocessor
		 * debug registers
		 */
		clk_enable(dbg_clk);
	}

	return TEE_SUCCESS;
}
early_init_late(init_debug);
#endif /* CFG_STM32_DEBUG_ACCESS */

/* Some generic resources need to be unpaged */
DECLARE_KEEP_PAGER(pinctrl_apply_state);
