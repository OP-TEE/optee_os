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

#ifndef __DRIVERS_APLIC_PRIV_H
#define __DRIVERS_APLIC_PRIV_H

#include <io.h>
#include <kernel/interrupt.h>
#include <types_ext.h>
#include <util.h>

#define APLIC_MAX_SOURCE                  1024
#define APLIC_COMPATIBLE                  "riscv,aplic"

/* APLIC registers */
#define APLIC_DOMAINCFG                   0x0000
#define APLIC_DOMAINCFG_RDONLY            0x80000000
#define APLIC_DOMAINCFG_IE                BIT(8)
#define APLIC_DOMAINCFG_DM                BIT(2)
#define APLIC_DOMAINCFG_BE                BIT(0)

#define APLIC_SOURCECFG_BASE              0x0004	/* sourcecfg[1] */
#define APLIC_SOURCECFG_D                 BIT(10)
#define APLIC_SOURCECFG_CHILDIDX_MASK     GENMASK_32(9, 0)
#define APLIC_SOURCECFG_SM_MASK           GENMASK_32(2, 0)
#define APLIC_SOURCECFG_SM_INACTIVE       0x0
#define APLIC_SOURCECFG_SM_DETACHED       0x1
#define APLIC_SOURCECFG_SM_EDGE_RISE      0x4
#define APLIC_SOURCECFG_SM_EDGE_FALL      0x5
#define APLIC_SOURCECFG_SM_LEVEL_HIGH     0x6
#define APLIC_SOURCECFG_SM_LEVEL_LOW      0x7

#define APLIC_MMSIADDRCFG                 0x1BC0
#define APLIC_MMSIADDRCFGH                0x1BC4
#define APLIC_SMSIADDRCFG                 0x1BC8
#define APLIC_SMSIADDRCFGH                0x1BCC

#define APLIC_SETIP_BASE                  0x1C00
#define APLIC_SETIPNUM                    0x1CDC
#define APLIC_IN_CLRIP_BASE               0x1D00
#define APLIC_CLRIPNUM                    0x1DDC
#define APLIC_SETIE_BASE                  0x1E00
#define APLIC_SETIENUM                    0x1EDC
#define APLIC_CLRIE_BASE                  0x1F00
#define APLIC_CLRIENUM                    0x1FDC
#define APLIC_SETIPNUM_LE                 0x2000
#define APLIC_SETIPNUM_BE                 0x2004
#define APLIC_GENMSI                      0x3000

#define APLIC_TARGET_BASE                 0x3004	/* target[1] */
#define APLIC_TARGET_HART_IDX_SHIFT       18
#define APLIC_TARGET_HART_IDX_MASK        GENMASK_32(31, 18)
#define APLIC_TARGET_GUEST_IDX_SHIFT      12
#define APLIC_TARGET_GUEST_IDX_MASK       GENMASK_32(17, 12)
#define APLIC_TARGET_EIID_MASK            GENMASK_32(10, 0)
#define APLIC_TARGET_IPRIO_MASK           GENMASK_32(7, 0)

/*
 * struct aplic_data - APLIC interrupt controller
 * @aplic_base: Base address of the APLIC
 * @size: Size of the APLIC in bytes
 * @targets_mmode: Indicates if APLIC targets Machine mode (true) or not (false)
 * @num_idc: Number of interrupt delivery control structures supported by APLIC
 * @num_source: Number of interrupt sources supported by APLIC
 * @chip: Interrupt controller base class
 */
struct aplic_data {
	vaddr_t aplic_base;
	uint32_t size;
	bool targets_mmode;
	uint32_t num_idc;
	uint32_t num_source;
	struct itr_chip chip;
};

static inline void aplic_enable_interrupt(struct aplic_data *aplic,
					  uint32_t source)
{
	io_write32(aplic->aplic_base + APLIC_SETIENUM, source);
}

static inline void aplic_disable_interrupt(struct aplic_data *aplic,
					   uint32_t source)
{
	io_write32(aplic->aplic_base + APLIC_CLRIENUM, source);
}

static inline void aplic_set_pending(struct aplic_data *aplic, uint32_t source)
{
	io_write32(aplic->aplic_base + APLIC_SETIPNUM, source);
}

static inline void aplic_clear_pending(struct aplic_data *aplic,
				       uint32_t source)
{
	io_write32(aplic->aplic_base + APLIC_CLRIPNUM, source);
}

static inline bool aplic_is_bad_it(struct aplic_data *aplic, size_t it)
{
	return !it || it > aplic->num_source;
}

TEE_Result aplic_init_from_device_tree(struct aplic_data *aplic);
TEE_Result aplic_set_source_mode(struct aplic_data *aplic, uint32_t source,
				 uint32_t type);

#endif /* __DRIVERS_APLIC_PRIV_H */
