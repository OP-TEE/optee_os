// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Huang Borong <huangborong@bosc.ac.cn>
 */

#include <compiler.h>
#include <drivers/imsic.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <riscv.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#define IMSIC_MMIO_PAGE_SHIFT     12
#define IMSIC_MMIO_PAGE_SZ        BIT(IMSIC_MMIO_PAGE_SHIFT)

#define IMSIC_MIN_ID              63
#define IMSIC_MAX_ID              2048

#define IMSIC_TOPEI_ID_SHIFT      16

#define IMSIC_IPI_ID              1

#define IMSIC_COMPATIBLE          "riscv,imsics"

/* IMSIC CSRs */
#define IMSIC_EIDELIVERY          0x70
#define IMSIC_EITHRESHOLD         0x72

#define IMSIC_EIP0                0x80
#define IMSIC_EIP63               0xBF
#define IMSIC_EIPx_BITS           32

#define IMSIC_EIE0                0xC0
#define IMSIC_EIE63               0xFF
#define IMSIC_EIEx_BITS           32

#define IMSIC_DISABLE_EIDELIVERY  0
#define IMSIC_ENABLE_EIDELIVERY   1

#define IMSIC_DISABLE_EITHRESHOLD 1
#define IMSIC_ENABLE_EITHRESHOLD  0

static struct imsic_data imsic_data __nex_bss;

/*
 * The IMSIC CSRs need to be indirectly accessed through
 * the *iselect(miselect/siselect) and *ireg(mireg/sireg) CSRs.
 */
static void imsic_csr_write(unsigned long reg, unsigned long val)
{
	write_csr(CSR_XISELECT, reg);
	write_csr(CSR_XIREG, val);
}

static unsigned long __unused imsic_csr_read(unsigned long reg)
{
	write_csr(CSR_XISELECT, reg);
	return read_csr(CSR_XIREG);
}

static void imsic_csr_set(unsigned long reg, unsigned long val)
{
	write_csr(CSR_XISELECT, reg);
	set_csr(CSR_XIREG, val);
}

static void imsic_csr_clear(unsigned long reg, unsigned long val)
{
	write_csr(CSR_XISELECT, reg);
	clear_csr(CSR_XIREG, val);
}

static void imsic_enable_interrupt_delivery(void)
{
	imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
}

static void __unused imsic_disable_interrupt_delivery(void)
{
	imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_DISABLE_EIDELIVERY);
}

static void imsic_enable_interrupt_threshold(void)
{
	imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
}

static void __unused imsic_disable_interrupt_threshold(void)
{
	imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_DISABLE_EITHRESHOLD);
}

static uint32_t imsic_claim_interrupt(void)
{
	uint32_t val = swap_csr(CSR_XTOPEI, 0);

	return val >> IMSIC_TOPEI_ID_SHIFT;
}

static void imsic_local_eix_update(uint32_t base_id, uint32_t num_id,
				   bool pend, bool val)
{
	uint32_t i = 0;
	uint32_t isel = 0;
	uint32_t ireg = 0;
	uint32_t id = base_id;
	uint32_t last_id = base_id + num_id;

	while (id < last_id) {
		isel = ROUNDDOWN(id, RISCV_XLEN_BITS) / IMSIC_EIPx_BITS;
		isel += (pend) ? IMSIC_EIP0 : IMSIC_EIE0;

		ireg = 0;
		for (i = id & (RISCV_XLEN_BITS - 1);
		     (id < last_id) && (i < RISCV_XLEN_BITS); i++) {
			ireg |= BIT(i);
			id++;
		}

		if (val)
			imsic_csr_set(isel, ireg);
		else
			imsic_csr_clear(isel, ireg);
	}
}

static void imsic_it_enable(uint32_t id)
{
	imsic_local_eix_update(id, 1, false, true);
}

static void imsic_it_disable(uint32_t id)
{
	imsic_local_eix_update(id, 1, false, false);
}

static void imsic_it_set_pending(uint32_t id)
{
	imsic_local_eix_update(id, 1, true, true);
}

static void imsic_it_clear_pending(uint32_t id)
{
	imsic_local_eix_update(id, 1, true, false);
}

static bool imsic_is_bad_it(struct imsic_data *imsic, size_t it)
{
	assert(imsic == &imsic_data);
	return (!it || it > imsic->num_ids);
}

static void imsic_op_configure(struct itr_chip *chip, size_t it,
			       uint32_t type, uint32_t prio __unused)
{
	struct imsic_data *imsic = container_of(chip, struct imsic_data, chip);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (imsic_is_bad_it(imsic, it))
		panic();

	if (imsic->aplic_chip) {
		res = interrupt_configure(imsic->aplic_chip, it, type, prio);
		if (res)
			panic();
	}
	imsic_it_disable(it);
	imsic_it_clear_pending(it);
}

static void imsic_op_enable(struct itr_chip *chip, size_t it)
{
	struct imsic_data *imsic = container_of(chip, struct imsic_data, chip);

	if (imsic_is_bad_it(imsic, it))
		panic();

	if (imsic->aplic_chip)
		interrupt_enable(imsic->aplic_chip, it);
	imsic_it_enable(it);
}

static void imsic_op_disable(struct itr_chip *chip, size_t it)
{
	struct imsic_data *imsic = container_of(chip, struct imsic_data, chip);

	if (imsic_is_bad_it(imsic, it))
		panic();

	imsic_it_disable(it);
	if (imsic->aplic_chip)
		interrupt_disable(imsic->aplic_chip, it);
}

static void imsic_op_raise_pi(struct itr_chip *chip, size_t it)
{
	struct imsic_data *imsic = container_of(chip, struct imsic_data, chip);

	if (imsic_is_bad_it(imsic, it))
		panic();

	imsic_it_set_pending(it);
}

static const struct itr_ops imsic_ops = {
	.configure = imsic_op_configure,
	.enable = imsic_op_enable,
	.disable = imsic_op_disable,
	.mask = imsic_op_disable,
	.unmask = imsic_op_enable,
	.raise_pi = imsic_op_raise_pi,
};

static void imsic_init_base_addr(paddr_t imsic_base_pa)
{
	struct imsic_data *imsic = &imsic_data;
	vaddr_t imsic_base = 0;

	assert(cpu_mmu_enabled());

	imsic_base = core_mmu_get_va(imsic_base_pa, MEM_AREA_IO_SEC,
				     IMSIC_SIZE);
	if (!imsic_base)
		panic();

	imsic->imsic_base = imsic_base;
	imsic->size = IMSIC_SIZE;
	imsic->targets_mmode = false;
	imsic->num_ids = IMSIC_NUM_IDS;
	imsic->guest_index_bits = IMSIC_GUEST_INDEX_BITS;
	imsic->hart_index_bits = IMSIC_HART_INDEX_BITS;
	imsic->group_index_bits = IMSIC_GROUP_INDEX_BITS;
	imsic->group_index_shift = IMSIC_GROUP_INDEX_SHIFT;
}

#if defined(CFG_DT) && defined(CFG_RISCV_IMSIC)
TEE_Result imisc_parse_fdt_node(const void *fdt, int nodeoff,
				struct imsic_data *imsic)
{
	const fdt32_t *val = NULL;
	paddr_t reg_addr = 0;
	size_t reg_size = 0;
	int i = 0;
	int rc = -1;
	int len = 0;

	if (nodeoff < 0 || !imsic || !fdt)
		return TEE_ERROR_BAD_PARAMETERS;

	rc = fdt_reg_info(fdt, nodeoff, &reg_addr, &reg_size);
	if (rc < 0 || !reg_addr || !reg_size)
		return TEE_ERROR_ITEM_NOT_FOUND;
	imsic->imsic_base = core_mmu_get_va(reg_addr, MEM_AREA_IO_SEC,
					    reg_size);
	if (!imsic->imsic_base)
		return TEE_ERROR_GENERIC;
	imsic->size = reg_size;

	imsic->targets_mmode = false;
	val = fdt_getprop(fdt, nodeoff, "interrupts-extended", &len);
	if (val && (size_t)len >= (2 * sizeof(fdt32_t))) {
		len = len / sizeof(fdt32_t);
		for (i = 0; i < len; i += 2) {
			if (fdt32_to_cpu(val[i + 1]) == IRQ_M_EXT) {
				imsic->targets_mmode = true;
				break;
			}
		}
	} else {
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	val = fdt_getprop(fdt, nodeoff, "riscv,guest-index-bits", &len);
	if (val && len > 0)
		imsic->guest_index_bits = fdt32_to_cpu(*val);
	else
		imsic->guest_index_bits = 0;

	val = fdt_getprop(fdt, nodeoff, "riscv,hart-index-bits", &len);
	if (val && len > 0)
		imsic->hart_index_bits = fdt32_to_cpu(*val);
	else
		imsic->hart_index_bits =
			32 - __builtin_clz(CFG_TEE_CORE_NB_CORE - 1);

	val = fdt_getprop(fdt, nodeoff, "riscv,group-index-bits", &len);
	if (val && len > 0)
		imsic->group_index_bits = fdt32_to_cpu(*val);
	else
		imsic->group_index_bits = 0;

	val = fdt_getprop(fdt, nodeoff, "riscv,group-index-shift", &len);
	if (val && len > 0)
		imsic->group_index_shift = fdt32_to_cpu(*val);
	else
		imsic->group_index_shift = 2 * IMSIC_MMIO_PAGE_SHIFT;

	val = fdt_getprop(fdt, nodeoff, "riscv,num-ids", &len);
	if (val && len > 0)
		imsic->num_ids = fdt32_to_cpu(*val);
	else
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}
#endif

static TEE_Result imsic_init_from_device_tree(struct imsic_data *imsic)
{
	void *fdt = NULL;
	int node = FDT_ERR_NOTFOUND;
	TEE_Result res = TEE_ERROR_GENERIC;

	fdt = get_dt();
	if (!fdt) {
		EMSG("Unable to get DTB, IMSIC init failed");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/*
	 * Currently, only the S-level interrupt file is considered.
	 * If the interrupt file is M-level, continue traversing.
	 * If it is S-level, return directly.
	 */
	node = fdt_node_offset_by_compatible(fdt, -1, IMSIC_COMPATIBLE);
	while (node != -FDT_ERR_NOTFOUND) {
		res = imisc_parse_fdt_node(fdt, node, imsic);
		if (res) {
			EMSG("Parse IMSIC node failed");
			return res;
		}
		if (!imsic->targets_mmode)
			return TEE_SUCCESS;
		node = fdt_node_offset_by_compatible(fdt, node,
						     IMSIC_COMPATIBLE);
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

void imsic_it_handle(void)
{
	struct imsic_data *imsic = &imsic_data;
	uint32_t id = imsic_claim_interrupt();

	if (id == IMSIC_IPI_ID)
		DMSG("Interprocessor interrupt");

	if (id > IMSIC_IPI_ID && id <= imsic->num_ids)
		interrupt_call_handlers(&imsic->chip, id);
	else
		DMSG("ignoring interrupt %" PRIu32, id);
}

void imsic_init_per_hart(void)
{
	struct imsic_data *imsic = &imsic_data;

	imsic_local_eix_update(1, imsic->num_ids, false, false);
	imsic_enable_interrupt_threshold();
	imsic_enable_interrupt_delivery();
}

void imsic_init(paddr_t imsic_base_pa)
{
	struct imsic_data *imsic = &imsic_data;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (IS_ENABLED(CFG_DT)) {
		res = imsic_init_from_device_tree(imsic);
		if (res)
			panic();
	} else {
		imsic_init_base_addr(imsic_base_pa);
	}

	imsic->chip.ops = &imsic_ops;

	imsic_init_per_hart();

	imsic->aplic_chip = interrupt_get_main_chip();

	interrupt_main_init(&imsic->chip);
}

void imsic_dump_state(void)
{
}
