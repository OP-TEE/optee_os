// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2024, STMicroelectronics
 * Copyright (c) 2016-2018, Linaro Limited
 */

#include <boot_api.h>
#include <config.h>
#include <console.h>
#include <drivers/firewall_device.h>
#include <drivers/gic.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_bsec.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32_iwdg.h>
#include <drivers/stm32_uart.h>
#include <drivers/stm32mp_dt_bindings.h>
#ifdef CFG_STM32MP15
#include <drivers/stm32mp1_rcc.h>
#endif
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
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
	} uarts[] = {
		[0] = { .pa = 0 },
		[1] = { .pa = USART1_BASE },
		[2] = { .pa = USART2_BASE },
		[3] = { .pa = USART3_BASE },
		[4] = { .pa = UART4_BASE },
		[5] = { .pa = UART5_BASE },
		[6] = { .pa = USART6_BASE },
		[7] = { .pa = UART7_BASE },
		[8] = { .pa = UART8_BASE },
	};

	COMPILE_TIME_ASSERT(ARRAY_SIZE(uarts) > CFG_STM32_EARLY_CONSOLE_UART);

	if (!uarts[CFG_STM32_EARLY_CONSOLE_UART].pa)
		return;

	/* No clock yet bound to the UART console */
	console_data.clock = NULL;

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
	IMSG("DTB enables console");
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
#endif /* CFG_WITH_PAGER */
#endif /* CFG_STM32MP15 */

static TEE_Result secure_pager_ram(struct dt_driver_provider *fw_provider,
				   unsigned int decprot_id,
				   paddr_t base, size_t secure_size)
{
	/* Lock firewall configuration for secure internal RAMs used by pager */
	uint32_t query_arg = DECPROT(decprot_id, DECPROT_S_RW, DECPROT_LOCK);
	struct firewall_query fw_query = {
		.ctrl = dt_driver_provider_priv_data(fw_provider),
		.args = &query_arg,
		.arg_count = 1,
	};
	TEE_Result res = TEE_ERROR_GENERIC;
	bool is_pager_ram = false;

#if defined(CFG_WITH_PAGER)
	is_pager_ram = core_is_buffer_intersect(CFG_TZSRAM_START,
						CFG_TZSRAM_SIZE,
						base, secure_size);
#endif
	if (!is_pager_ram)
		return TEE_SUCCESS;

	res = firewall_set_memory_configuration(&fw_query, base, secure_size);
	if (res)
		EMSG("Failed to configure secure SRAM %#"PRIxPA"..%#"PRIxPA,
		     base, base + secure_size);

	return res;
}

static TEE_Result non_secure_scmi_ram(struct dt_driver_provider *fw_provider,
				      unsigned int decprot_id,
				      paddr_t base, size_t size)
{
	/* Do not lock firewall configuration for non-secure internal RAMs */
	uint32_t query_arg = DECPROT(decprot_id, DECPROT_NS_RW, DECPROT_UNLOCK);
	struct firewall_query fw_query = {
		.ctrl = dt_driver_provider_priv_data(fw_provider),
		.args = &query_arg,
		.arg_count = 1,
	};
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!core_is_buffer_intersect(CFG_STM32MP1_SCMI_SHM_BASE,
				      CFG_STM32MP1_SCMI_SHM_SIZE,
				      base, size))
		return TEE_SUCCESS;

	res = firewall_set_memory_configuration(&fw_query, base, size);
	if (res)
		EMSG("Failed to configure non-secure SRAM %#"PRIxPA"..%#"PRIxPA,
		     base, base + size);

	return res;
}

/* At run time we enforce that SRAM1 to SRAM4 are properly assigned if used */
static void configure_srams(struct dt_driver_provider *fw_provider)
{
	bool error = false;

	if (IS_ENABLED(CFG_WITH_PAGER)) {
		if (secure_pager_ram(fw_provider, STM32MP1_ETZPC_SRAM1_ID,
				     SRAM1_BASE, SRAM1_SIZE))
			error = true;

		if (secure_pager_ram(fw_provider, STM32MP1_ETZPC_SRAM2_ID,
				     SRAM2_BASE, SRAM2_SIZE))
			error = true;

		if (secure_pager_ram(fw_provider, STM32MP1_ETZPC_SRAM3_ID,
				     SRAM3_BASE, SRAM3_SIZE))
			error = true;

#if defined(CFG_STM32MP15)
		if (secure_pager_ram(fw_provider, STM32MP1_ETZPC_SRAM4_ID,
				     SRAM4_BASE, SRAM4_SIZE))
			error = true;
#endif
	}
	if (CFG_STM32MP1_SCMI_SHM_BASE) {
		if (non_secure_scmi_ram(fw_provider, STM32MP1_ETZPC_SRAM1_ID,
					SRAM1_BASE, SRAM1_SIZE))
			error = true;

		if (non_secure_scmi_ram(fw_provider, STM32MP1_ETZPC_SRAM2_ID,
					SRAM2_BASE, SRAM2_SIZE))
			error = true;

		if (non_secure_scmi_ram(fw_provider, STM32MP1_ETZPC_SRAM3_ID,
					SRAM3_BASE, SRAM3_SIZE))
			error = true;

#if defined(CFG_STM32MP15)
		if (non_secure_scmi_ram(fw_provider, STM32MP1_ETZPC_SRAM4_ID,
					SRAM4_BASE, SRAM4_SIZE))
			error = true;
#endif
	}

	if (error)
		panic();
}

static void configure_sysram(struct dt_driver_provider *fw_provider)
{
	uint32_t query_arg = DECPROT(ETZPC_TZMA1_ID, DECPROT_S_RW,
				     DECPROT_UNLOCK);
	struct firewall_query firewall = {
		.ctrl = dt_driver_provider_priv_data(fw_provider),
		.args = &query_arg,
		.arg_count = 1,
	};
	TEE_Result res = TEE_ERROR_GENERIC;

	res = firewall_set_memory_configuration(&firewall, SYSRAM_BASE,
						SYSRAM_SEC_SIZE);
	if (res)
		panic("Unable to secure SYSRAM");

	if (SYSRAM_SIZE > SYSRAM_SEC_SIZE) {
		size_t nsec_size = SYSRAM_SIZE - SYSRAM_SEC_SIZE;
		paddr_t nsec_start = SYSRAM_BASE + SYSRAM_SEC_SIZE;
		uint8_t *va = phys_to_virt(nsec_start, MEM_AREA_IO_NSEC,
					   nsec_size);

		IMSG("Non-secure SYSRAM [%p %p]", va, va + nsec_size - 1);

		/* Clear content from the non-secure part */
		memset(va, 0, nsec_size);
	}
}

static TEE_Result init_late_stm32mp1_drivers(void)
{
	uint32_t __maybe_unused state = 0;

	/* Configure SYSRAM and SRAMx secure hardening */
	if (IS_ENABLED(CFG_STM32_ETZPC)) {
		struct dt_driver_provider *prov = NULL;
		int node = 0;

		node = fdt_node_offset_by_compatible(get_embedded_dt(), -1,
						     "st,stm32-etzpc");
		if (node < 0)
			panic("Could not get ETZPC node");

		prov = dt_driver_get_provider_by_node(node, DT_DRIVER_FIREWALL);
		assert(prov);

		configure_sysram(prov);
		configure_srams(prov);
	}

#ifdef CFG_STM32MP15
	/* Device in Secure Closed state require RCC secure hardening */
	if (stm32_bsec_get_state(&state))
		panic();
	if (state == BSEC_STATE_SEC_CLOSED && !stm32_rcc_is_secure())
		panic("Closed device mandates secure RCC");
#endif

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

bool stm32mp_allow_probe_shared_device(const void *fdt, int node)
{
	static int uart_console_node = -1;
	const char *compat = NULL;
	static bool once;

	if (IS_ENABLED(CFG_STM32_ALLOW_UNSAFE_PROBE))
		return true;

	if (!once) {
		get_console_node_from_dt((void *)fdt, &uart_console_node,
					 NULL, NULL);
		once = true;
	}

	compat = fdt_stringlist_get(fdt, node, "compatible", 0, NULL);

	/*
	 * Allow OP-TEE console and MP15 I2C and RNG to be shared
	 * with non-secure world.
	 */
	if (node == uart_console_node ||
	    !strcmp(compat, "st,stm32mp15-i2c-non-secure") ||
	    (!strcmp(compat, "st,stm32-rng") &&
	     IS_ENABLED(CFG_WITH_SOFTWARE_PRNG)))
		return true;

	return false;
}

#if defined(CFG_STM32MP15) && defined(CFG_WITH_PAGER)
paddr_t stm32mp1_pa_or_sram_alias_pa(paddr_t pa)
{
	/*
	 * OP-TEE uses the alias physical addresses of SRAM1/2/3/4,
	 * not the standard physical addresses. This choice was initially
	 * driven by pager that needs physically contiguous memories
	 * for internal secure memories.
	 */
	if (core_is_buffer_inside(pa, 1, SRAM1_ALT_BASE, SRAM1_SIZE))
		pa += SRAM1_BASE - SRAM1_ALT_BASE;
	else if (core_is_buffer_inside(pa, 1, SRAM2_ALT_BASE, SRAM2_SIZE))
		pa += SRAM2_BASE - SRAM2_ALT_BASE;
	else if (core_is_buffer_inside(pa, 1, SRAM3_ALT_BASE, SRAM3_SIZE))
		pa += SRAM3_BASE - SRAM3_ALT_BASE;
	else if (core_is_buffer_inside(pa, 1, SRAM4_ALT_BASE, SRAM4_SIZE))
		pa += SRAM4_BASE - SRAM4_ALT_BASE;

	return pa;
}

bool stm32mp1_ram_intersect_pager_ram(paddr_t base, size_t size)
{
	base = stm32mp1_pa_or_sram_alias_pa(base);

	return core_is_buffer_intersect(base, size, CFG_TZSRAM_START,
					CFG_TZSRAM_SIZE);
}
#endif
