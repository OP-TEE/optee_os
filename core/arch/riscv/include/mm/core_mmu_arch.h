/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */
#ifndef __MM_CORE_MMU_ARCH_H
#define __MM_CORE_MMU_ARCH_H

#ifndef __ASSEMBLER__
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <riscv.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <platform_config.h>

#ifdef TRUSTED_DRAM_BASE
#error TRUSTED_DRAM_BASE is already defined
#endif
#define TRUSTED_DRAM_BASE	TDDRAM_BASE
#define TRUSTED_DRAM_SIZE	TDDRAM_SIZE

/* MMU defines */
#ifdef CFG_RISCV_MMU_MODE
#define RISCV_MMU_MODE		CFG_RISCV_MMU_MODE
#else
#ifdef RV64
#define RISCV_MMU_MODE		U(39)
#else
#define RISCV_MMU_MODE		U(32)
#endif
#endif

#if RISCV_MMU_MODE == 57	/*Sv57*/
#define RISCV_SATP_MODE	SATP_MODE_SV57
#define RISCV_SATP_MODE_SHIFT	U(60)
#define RISCV_SATP_ASID_SHIFT	U(44)
#define RISCV_SATP_ASID_WIDTH	U(16)
#define RISCV_SATP_ASID_MASK	0x0FFFF
#define RISCV_MMU_PA_WIDTH	U(56)
#define RISCV_MMU_VA_WIDTH	U(57)
#elif RISCV_MMU_MODE == 48	/*Sv48*/
#define RISCV_SATP_MODE	SATP_MODE_SV48
#define RISCV_SATP_MODE_SHIFT	U(60)
#define RISCV_SATP_ASID_SHIFT	U(44)
#define RISCV_SATP_ASID_WIDTH	U(16)
#define RISCV_SATP_ASID_MASK	0x0FFFF
#define RISCV_MMU_PA_WIDTH	U(56)
#define RISCV_MMU_VA_WIDTH	U(48)
#elif RISCV_MMU_MODE == 39	/*Sv39*/
#define RISCV_SATP_MODE	SATP_MODE_SV39
#define RISCV_SATP_MODE_SHIFT	U(60)
#define RISCV_SATP_ASID_SHIFT	U(44)
#define RISCV_SATP_ASID_WIDTH	U(16)
#define RISCV_SATP_ASID_MASK	0x0FFFF
#define RISCV_MMU_PA_WIDTH	U(56)
#define RISCV_MMU_VA_WIDTH	U(39)
#elif RISCV_MMU_MODE == 32	/*Sv32*/
#define RISCV_SATP_MODE	SATP_MODE_SV32
#define RISCV_SATP_MODE_SHIFT	U(31)
#define RISCV_SATP_ASID_SHIFT	U(22)
#define RISCV_SATP_ASID_WIDTH	U(9)
#define RISCV_SATP_ASID_MASK	0x01FF
#define RISCV_MMU_PA_WIDTH	U(32)
#define RISCV_MMU_VA_WIDTH	U(32)
#else
#error unknown or unsupported mmu mode
#endif

#define RISCV_PTES_PER_PT	BIT(RISCV_PGLEVEL_BITS)
#define RISCV_PGLEVELS		((RISCV_MMU_VA_WIDTH - RISCV_PGSHIFT) / \
							 RISCV_PGLEVEL_BITS)
#define RISCV_MMU_VPN_MASK	(BIT(RISCV_PGLEVEL_BITS) - 1)
#define RISCV_MMU_MAX_PGTS	16

#define SMALL_PAGE_SHIFT	U(12)

/*
 * RV32:
 * Level 0, shift = 12, 4 KiB pages
 * Level 1, shift = 22, 4 MiB pages
 *
 * RV64:
 * Level 0, shift = 12, 4 KiB pages
 * Level 1, shift = 21, 2 MiB pages
 * Level 2, shift = 30, 1 GiB pages
 * Level 3, shift = 39, 512 GiB pages
 * Level 4, shift = 48, 256 TiB pages
 */
#define CORE_MMU_SHIFT_OF_LEVEL(level) (RISCV_PGLEVEL_BITS * \
					(level) + \
					RISCV_PGSHIFT)

#ifdef RV64
#define CORE_MMU_PAGE_OFFSET_MASK(level) \
		GENMASK_64(CORE_MMU_SHIFT_OF_LEVEL(level) - 1, 0)
#else
#define CORE_MMU_PAGE_OFFSET_MASK(level) \
		GENMASK_32(CORE_MMU_SHIFT_OF_LEVEL(level) - 1, 0)
#endif

#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT

/*
 * In all MMU modes, the CORE_MMU_PGDIR_LEVEL is always 0:
 * Sv32: 4 MiB, 4 KiB
 *                                       +-------------------------------------+
 *                                       |31      22 21      12 11            0|
 *                                       |-------------------------------------+
 *                                       |  VPN[1]  |  VPN[0]  |  page offset  |
 *                                       +-------------------------------------+
 * Sv39: 1 GiB, 2 MiB, 4 KiB
 *                            +------------------------------------------------+
 *                            |38      30 29      21 20      12 11            0|
 *                            |------------------------------------------------+
 *                            |  VPN[2]  |  VPN[1]  |  VPN[0]  |  page offset  |
 *                            +------------------------------------------------+
 * Sv48: 512 GiB, 1 GiB, 2 MiB, 4 KiB
 *                 +-----------------------------------------------------------+
 *                 |47      39 38      30 29      21 20      12 11            0|
 *                 |-----------------------------------------------------------+
 *                 |  VPN[3]  |  VPN[2]  |  VPN[1]  |  VPN[0]  |  page offset  |
 *                 +-----------------------------------------------------------+
 * Sv57: 256 TiB, 512 GiB, 1 GiB, 2 MiB, 4 KiB
 *      +----------------------------------------------------------------------+
 *      |56      48 47      39 38      30 29      21 20      12 11            0|
 *      |----------------------------------------------------------------------+
 *      |  VPN[4]  |  VPN[3]  |  VPN[2]  |  VPN[1]  |  VPN[0]  |  page offset  |
 *      +----------------------------------------------------------------------+
 */
#define CORE_MMU_VPN0_LEVEL		U(0)
#define CORE_MMU_VPN1_LEVEL		U(1)
#define CORE_MMU_VPN2_LEVEL		U(2)
#define CORE_MMU_VPN3_LEVEL		U(3)
#define CORE_MMU_VPN4_LEVEL		U(4)
#define CORE_MMU_VPN0_SHIFT		\
	CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_VPN0_LEVEL)
#define CORE_MMU_VPN1_SHIFT		\
	CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_VPN1_LEVEL)
#define CORE_MMU_VPN2_SHIFT		\
	CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_VPN2_LEVEL)
#define CORE_MMU_VPN3_SHIFT		\
	CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_VPN3_LEVEL)
#define CORE_MMU_VPN4_SHIFT		\
	CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_VPN4_LEVEL)

#define CORE_MMU_PGDIR_LEVEL		CORE_MMU_VPN0_LEVEL
#define CORE_MMU_PGDIR_SHIFT \
		CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_PGDIR_LEVEL + 1)

#define CORE_MMU_BASE_TABLE_LEVEL	(RISCV_PGLEVELS - 1)
#define CORE_MMU_BASE_TABLE_SHIFT \
		CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_BASE_TABLE_LEVEL)

#ifndef __ASSEMBLER__

struct core_mmu_config {
	unsigned long satp[CFG_TEE_CORE_NB_CORE];
	unsigned long map_offset;
};

struct core_mmu_user_map {
	unsigned long user_map;
	uint32_t asid;
};

/* Cache maintenance operation type */
enum cache_op {
	DCACHE_CLEAN,
	DCACHE_AREA_CLEAN,
	DCACHE_INVALIDATE,
	DCACHE_AREA_INVALIDATE,
	ICACHE_INVALIDATE,
	ICACHE_AREA_INVALIDATE,
	DCACHE_CLEAN_INV,
	DCACHE_AREA_CLEAN_INV,
};

static inline void core_mmu_table_write_barrier(void)
{
	/* Invoke memory barrier */
	mb();
}

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len);

static inline bool core_mmu_check_max_pa(paddr_t pa)
{
	return pa <= (BIT64(RISCV_MMU_PA_WIDTH) - 1);
}

static inline unsigned int core_mmu_get_va_width(void)
{
	return RISCV_MMU_VA_WIDTH;
}

static inline bool core_mmu_va_is_valid(vaddr_t va)
{
#ifdef RV32
	return va < BIT64(core_mmu_get_va_width());
#else
	/*
	 * Validates if a RV64 virtual address is valid.
	 * For each RV64 MMU mode, the upper bits must be
	 * extended from the highest valid VA bit:
	 * - Sv39: va[63:39] must equal to bit 38
	 * - Sv48: va[63:48] must equal to bit 47
	 * - Sv57: va[63:57] must equal to bit 56
	 * Otherwise, a page-fault exception is raised.
	 */
	vaddr_t mask = GENMASK_64(63, RISCV_MMU_VA_WIDTH);
	uint64_t msb = BIT64(RISCV_MMU_VA_WIDTH - 1);

	if (va & msb)
		return (va & mask) == mask;

	return (va & mask) == 0;
#endif
}

static inline bool core_mmu_level_in_range(unsigned int level)
{
	return level <= CORE_MMU_BASE_TABLE_LEVEL;
}
#endif /*__ASSEMBLER__*/

#endif /* __MM_CORE_MMU_ARCH_H */
