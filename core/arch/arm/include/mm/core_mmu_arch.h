/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __MM_CORE_MMU_ARCH_H
#define __MM_CORE_MMU_ARCH_H

#ifndef __ASSEMBLER__
#include <arm.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <platform_config.h>

/*
 * Platforms can define TRUSTED_{S,D}RAM_* or TZ{S,D}RAM_*. We're helping
 * here with the transition to TRUSTED_{S,D}RAM_* by defining these if
 * missing based on the legacy defines.
 */
#ifdef TZSRAM_BASE
#ifdef TRUSTED_SRAM_BASE
#error TRUSTED_SRAM_BASE is already defined
#endif
#define TRUSTED_SRAM_BASE	TZSRAM_BASE
#define TRUSTED_SRAM_SIZE	TZSRAM_SIZE
#endif

#ifdef TZDRAM_BASE
#ifdef TRUSTED_DRAM_BASE
#error TRUSTED_DRAM_BASE is already defined
#endif
#define TRUSTED_DRAM_BASE	TZDRAM_BASE
#define TRUSTED_DRAM_SIZE	TZDRAM_SIZE
#endif

#define SMALL_PAGE_SHIFT	U(12)

#ifdef CFG_WITH_LPAE
#define CORE_MMU_PGDIR_SHIFT	U(21)
#define CORE_MMU_PGDIR_LEVEL	U(3)
#else
#define CORE_MMU_PGDIR_SHIFT	U(20)
#define CORE_MMU_PGDIR_LEVEL	U(2)
#endif

#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT

#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT

/*
 * Level of base table (i.e. first level of page table),
 * depending on address space
 */
#if !defined(CFG_WITH_LPAE) || (CFG_LPAE_ADDR_SPACE_BITS < 40)
#define CORE_MMU_BASE_TABLE_SHIFT	U(30)
#define CORE_MMU_BASE_TABLE_LEVEL	U(1)
#elif (CFG_LPAE_ADDR_SPACE_BITS <= 48)
#define CORE_MMU_BASE_TABLE_SHIFT	U(39)
#define CORE_MMU_BASE_TABLE_LEVEL	U(0)
#else /* (CFG_LPAE_ADDR_SPACE_BITS > 48) */
#error "CFG_WITH_LPAE with CFG_LPAE_ADDR_SPACE_BITS > 48 isn't supported!"
#endif

#ifdef CFG_WITH_LPAE
/*
 * CORE_MMU_BASE_TABLE_OFFSET is used when switching to/from reduced kernel
 * mapping. The actual value depends on internals in core_mmu_lpae.c which
 * we rather not expose here. There's a compile time assertion to check
 * that these magic numbers are correct.
 */
#define CORE_MMU_BASE_TABLE_OFFSET \
	(CFG_TEE_CORE_NB_CORE * \
	 BIT(CFG_LPAE_ADDR_SPACE_BITS - CORE_MMU_BASE_TABLE_SHIFT) * \
	 U(8))
#endif

#ifndef __ASSEMBLER__

/*
 * Assembly code in enable_mmu() depends on the layout of this struct.
 */
struct core_mmu_config {
#if defined(ARM64)
	uint64_t tcr_el1;
	uint64_t mair_el1;
	uint64_t ttbr0_el1_base;
	uint64_t ttbr0_core_offset;
	uint64_t map_offset;
#elif defined(CFG_WITH_LPAE)
	uint32_t ttbcr;
	uint32_t mair0;
	uint32_t ttbr0_base;
	uint32_t ttbr0_core_offset;
	uint32_t map_offset;
#else
	uint32_t prrr;
	uint32_t nmrr;
	uint32_t dacr;
	uint32_t ttbcr;
	uint32_t ttbr;
	uint32_t map_offset;
#endif
};

#ifdef CFG_WITH_LPAE
/*
 * struct core_mmu_user_map - current user mapping register state
 * @user_map:	physical address of user map translation table
 * @asid:	ASID for the user map
 *
 * Note that this struct should be treated as an opaque struct since
 * the content depends on descriptor table format.
 */
struct core_mmu_user_map {
	uint64_t user_map;
	uint32_t asid;
};
#else
/*
 * struct core_mmu_user_map - current user mapping register state
 * @ttbr0:	content of ttbr0
 * @ctxid:	content of contextidr
 *
 * Note that this struct should be treated as an opaque struct since
 * the content depends on descriptor table format.
 */
struct core_mmu_user_map {
	uint32_t ttbr0;
	uint32_t ctxid;
};
#endif

#ifdef CFG_WITH_LPAE
bool core_mmu_user_va_range_is_defined(void);
#else
static inline bool __noprof core_mmu_user_va_range_is_defined(void)
{
	return true;
}
#endif

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

/* L1/L2 cache maintenance */
TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len);
#ifdef CFG_PL310
TEE_Result cache_op_outer(enum cache_op op, paddr_t pa, size_t len);
#else
static inline TEE_Result cache_op_outer(enum cache_op op __unused,
					paddr_t pa __unused,
					size_t len __unused)
{
	/* Nothing to do about L2 Cache Maintenance when no PL310 */
	return TEE_SUCCESS;
}
#endif

/* Do section mapping, not support on LPAE */
void map_memarea_sections(const struct tee_mmap_region *mm, uint32_t *ttb);

#if defined(ARM64)
unsigned int core_mmu_arm64_get_pa_width(void);
#endif

static inline bool core_mmu_check_max_pa(paddr_t pa __maybe_unused)
{
#if defined(ARM64)
	return pa <= (BIT64(core_mmu_arm64_get_pa_width()) - 1);
#elif defined(CFG_CORE_LARGE_PHYS_ADDR)
	return pa <= (BIT64(40) - 1);
#else
	COMPILE_TIME_ASSERT(sizeof(paddr_t) == sizeof(uint32_t));
	return true;
#endif
}

/*
 * Special barrier to make sure all the changes to translation tables are
 * visible before returning.
 */
static inline void core_mmu_table_write_barrier(void)
{
	dsb_ishst();
}

static inline bool core_mmu_entry_have_security_bit(uint32_t attr)
{
	return !(attr & TEE_MATTR_TABLE) || !IS_ENABLED(CFG_WITH_LPAE);
}

static inline unsigned int core_mmu_get_va_width(void)
{
	if (IS_ENABLED(ARM64)) {
		COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_BITS >= 32);
		COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_BITS <= 48);
		return CFG_LPAE_ADDR_SPACE_BITS;
	}
	return 32;
}

static inline bool core_mmu_level_in_range(unsigned int level)
{
#if CORE_MMU_BASE_TABLE_LEVEL == 0
	return level <= CORE_MMU_PGDIR_LEVEL;
#else
	return level >= CORE_MMU_BASE_TABLE_LEVEL &&
	       level <= CORE_MMU_PGDIR_LEVEL;
#endif
}

#endif /*__ASSEMBLER__*/

#endif /* __MM_CORE_MMU_ARCH_H */
