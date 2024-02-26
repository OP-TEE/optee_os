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
#define RISCV_MMU_ASID_WIDTH	16
#else
#define RISCV_MMU_MODE		U(32)
#define RISCV_MMU_ASID_WIDTH	9
#endif
#endif

#if RISCV_MMU_MODE == 48	/*Sv48*/
#define RISCV_SATP_MODE	SATP_MODE_SV48
#define RISCV_SATP_MODE_SHIFT	U(60)
#define RISCV_SATP_ASID_SHIFT	U(44)
#define RISCV_SATP_ASID_SIZE	U(16)
#define RISCV_SATP_ASID_MASK	0x0FFFF
#define RISCV_MMU_PA_WIDTH	U(56)
#define RISCV_MMU_VA_WIDTH	U(48)
#elif RISCV_MMU_MODE == 39	/*Sv39*/
#define RISCV_SATP_MODE	SATP_MODE_SV39
#define RISCV_SATP_ASID_SHIFT	U(44)
#define RISCV_SATP_ASID_SIZE	U(16)
#define RISCV_SATP_ASID_MASK	0x0FFFF
#define RISCV_MMU_PA_WIDTH	U(56)
#define RISCV_MMU_VA_WIDTH	U(39)
#define RISCV_SATP_MODE_SHIFT 60
#elif RISCV_MMU_MODE == 32	/*Sv32*/
#define RISCV_SATP_MODE	SATP_MODE_SV32
#define RISCV_SATP_MODE_SHIFT	U(31)
#define RISCV_SATP_ASID_SHIFT	U(22)
#define RISCV_SATP_ASID_SIZE	U(9)
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
 * Level 0, shift = 12, 4 KiB pages
 * Level 1, shift = 21, 2 MiB pages (4 MiB pages in Sv32)
 * Level 2, shift = 30, 1 GiB pages
 * Level 3, shift = 39, 512 GiB pages
 * Level 4, shift = 48, 256 TiB pages
 */
#define CORE_MMU_SHIFT_OF_LEVEL(level) (RISCV_PGLEVEL_BITS * \
					(level) + \
					RISCV_PGSHIFT)

#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT

/*
 * In all MMU modes, the CORE_MMU_PGDIR_LEVEL is always 0:
 * Sv32: 4 KiB, 4 MiB
 * Sv39: 4 KiB, 2 MiB, 1 GiB
 * Sv48: 4 KiB, 2 MiB, 1 GiB, 512 GiB
 * Sv57: 4 KiB, 2 MiB, 1 GiB, 512 GiB, 256 TiB
 */
#define CORE_MMU_PGDIR_LEVEL		U(0)
#define CORE_MMU_PGDIR_SHIFT \
		CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_PGDIR_LEVEL + 1)

#define CORE_MMU_BASE_TABLE_LEVEL	(RISCV_PGLEVELS - 1)
#define CORE_MMU_BASE_TABLE_SHIFT \
		CORE_MMU_SHIFT_OF_LEVEL(CORE_MMU_BASE_TABLE_LEVEL)

#ifndef __ASSEMBLER__

struct core_mmu_config {
	unsigned long satp[CFG_TEE_CORE_NB_CORE];
	uint32_t map_offset;
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

static inline bool core_mmu_level_in_range(unsigned int level)
{
	return level <= CORE_MMU_BASE_TABLE_LEVEL;
}
#endif /*__ASSEMBLER__*/

#endif /* __MM_CORE_MMU_ARCH_H */
