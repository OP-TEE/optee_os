/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 * Copyright (c) 2025 Beijing Institute of Open Source Chip (BOSC)
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Huang Borong <huangborong@bosc.ac.cn>
 */

#ifndef __DRIVERS_IMSIC_H
#define __DRIVERS_IMSIC_H

#include <kernel/interrupt.h>
#include <tee_api_defines.h>
#include <types_ext.h>

/*
 * struct imsic_data - IMISC interrupt controller
 * @imsic_base: Base address of the interrupt file
 * @size: Size of the interrupt file in bytes
 * @targets_mmode: Indicates if IMSIC targets Machine mode (true) or not (false)
 * @num_ids: Number of interrupt identities supported by an interrupt file
 * @guest_index_bits: Number of guest index bits in the MSI target address
 * @hart_index_bits: Number of hart index bits in the MSI target address
 * @group_index_bits: Number of group index bits in the MSI target address
 * @group_index_shift: Number of bits to shift the group index
 * @aplic_chip: Pointer to the associated APLIC's itr_chip
 * @chip: Interrupt controller base class
 */
struct imsic_data {
	vaddr_t imsic_base;
	uint32_t size;
	bool targets_mmode;
	uint32_t num_ids;
	uint32_t guest_index_bits;
	uint32_t hart_index_bits;
	uint32_t group_index_bits;
	uint32_t group_index_shift;
	struct itr_chip *aplic_chip;
	struct itr_chip chip;
};

/*
 * The imsic_init() function initializes the struct imsic_data which
 * is then used by other functions. This function also initializes
 * the IMSIC and should only be called from the primary boot hart.
 */
void imsic_init(paddr_t imsic_base_pa);

/*
 * Does per-hart specific IMSIC initialization, should be called by all
 * secondary harts when booting.
 */
void imsic_init_per_hart(void);

/* Handle external interrupts */
void imsic_it_handle(void);

/* Print IMSIC state to console */
void imsic_dump_state(void);

#if defined(CFG_DT) && defined(CFG_RISCV_IMSIC)
/*
 * imisc_parse_fdt_node() - Parse the IMSIC node from the device tree
 *
 * @fdt: Device tree to work on
 * @nodeoff: Offset of the node in the device tree
 * @imsic: Pointer to an imsic_data structure to store parsed information
 *
 * Returns TEE_Result value
 */
TEE_Result imisc_parse_fdt_node(const void *fdt, int nodeoff,
				struct imsic_data *imsic);
#else
static inline TEE_Result
imisc_parse_fdt_node(const void *fdt __unused,
		     int nodeoff __unused, struct imsic_data *imsic __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /* __DRIVERS_IMSIC_H */
