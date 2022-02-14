/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __CORE_MMU_ARCH_H
#define __CORE_MMU_ARCH_H

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

#ifdef TDSRAM_BASE
#ifdef TRUSTED_SRAM_BASE
#error TRUSTED_SRAM_BASE is already defined
#endif
#define TRUSTED_SRAM_BASE	TDSRAM_BASE
#define TRUSTED_SRAM_SIZE	TDSRAM_SIZE
#endif

#ifdef TDDRAM_BASE
#ifdef TRUSTED_DRAM_BASE
#error TRUSTED_DRAM_BASE is already defined
#endif
#define TRUSTED_DRAM_BASE	TDDRAM_BASE
#define TRUSTED_DRAM_SIZE	TDDRAM_SIZE
#endif

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

#define RISCV_PTES_PER_PT (U(1) << RISCV_PGLEVEL_BITS)
#define RISCV_PGLEVELS ((RISCV_MMU_VA_WIDTH - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS)

#define SMALL_PAGE_SHIFT	RISCV_PGSHIFT

#define CORE_MMU_TABLE_LEVEL_STEP	-1
#define CORE_MMU_PGDIR_SHIFT	U(21)
#define CORE_MMU_PGDIR_LEVEL	U(1)

#define CORE_MMU_USER_CODE_SHIFT	RISCV_PGSHIFT
#define CORE_MMU_USER_PARAM_SHIFT	RISCV_PGSHIFT

/*
 * Level 0: shift = 12 4K pages
 * Level 1: shift = 21 2M pages
 * Level 2: shift = 30 1G pages 
 */
#define CORE_MMU_BASE_TABLE_LEVEL	(RISCV_PGLEVELS - 1)
#define CORE_MMU_BASE_TABLE_SHIFT	(RISCV_PGLEVEL_BITS * \
		CORE_MMU_BASE_TABLE_LEVEL + RISCV_PGSHIFT)

#ifndef STACK_ALIGNMENT
#define STACK_ALIGNMENT			U(16)
#endif

#ifndef __ASSEMBLER__

/*
 * Assembly code in enable_mmu() depends on the layout of this struct.
 */
struct core_mmu_config {
	unsigned long satp;
	unsigned long load_offset;
};

struct core_mmu_user_map {
	uint64_t user_map;
	uint32_t asid;
};

static inline bool __noprof core_mmu_user_va_range_is_defined(void)
{
	return true;
}

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

static inline TEE_Result cache_op_inner(enum cache_op op __unused,
		void *va __unused, size_t len __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result cache_op_outer(enum cache_op op __unused,
					paddr_t pa __unused,
					size_t len __unused)
{
	return TEE_SUCCESS;
}

static inline bool core_mmu_check_max_pa(paddr_t pa __maybe_unused)
{
	return pa <= (BIT64(RISCV_MMU_PA_WIDTH) - 1);
}

static inline void core_mmu_table_write_barrier(void)
{
	flush_tlb();
}

static inline bool core_mmu_entry_have_security_bit(uint32_t attr)
{
	return !(attr & TEE_MATTR_TABLE);
}

static inline unsigned int core_mmu_get_va_width(void)
{
	return RISCV_MMU_VA_WIDTH;
}

#endif /*__ASSEMBLER__*/

#endif /* CORE_MMU_H */
