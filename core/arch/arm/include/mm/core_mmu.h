/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef CORE_MMU_H
#define CORE_MMU_H

#include <assert.h>
#include <compiler.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <platform_config.h>
#include <types_ext.h>
#include <util.h>

/* A small page is the smallest unit of memory that can be mapped */
#define SMALL_PAGE_SHIFT	12
#define SMALL_PAGE_MASK		0x00000fff
#define SMALL_PAGE_SIZE		0x00001000

/*
 * PGDIR is the translation table above the translation table that holds
 * the pages.
 */
#ifdef CFG_WITH_LPAE
#define CORE_MMU_PGDIR_SHIFT	21
#else
#define CORE_MMU_PGDIR_SHIFT	20
#endif
#define CORE_MMU_PGDIR_SIZE		(1 << CORE_MMU_PGDIR_SHIFT)
#define CORE_MMU_PGDIR_MASK		(CORE_MMU_PGDIR_SIZE - 1)

/* Devices are mapped using this granularity */
#define CORE_MMU_DEVICE_SHIFT		CORE_MMU_PGDIR_SHIFT
#define CORE_MMU_DEVICE_SIZE		(1 << CORE_MMU_DEVICE_SHIFT)
#define CORE_MMU_DEVICE_MASK		(CORE_MMU_DEVICE_SIZE - 1)

/* TA user space code, data, stack and heap are mapped using this granularity */
#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_CODE_SIZE		(1 << CORE_MMU_USER_CODE_SHIFT)
#define CORE_MMU_USER_CODE_MASK		(CORE_MMU_USER_CODE_SIZE - 1)

/* TA user space parameters are mapped using this granularity */
#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_PARAM_SIZE	(1 << CORE_MMU_USER_PARAM_SHIFT)
#define CORE_MMU_USER_PARAM_MASK	(CORE_MMU_USER_PARAM_SIZE - 1)

#ifndef CFG_TEE_RAM_VA_SIZE
#define CFG_TEE_RAM_VA_SIZE		CORE_MMU_PGDIR_SIZE
#endif

#ifndef STACK_ALIGNMENT
#define STACK_ALIGNMENT			(sizeof(long) * 2)
#endif

/*
 * Memory area type:
 * MEM_AREA_END:      Reserved, marks the end of a table of mapping areas.
 * MEM_AREA_TEE_RAM:  core RAM (read/write/executable, secure, reserved to TEE)
 * MEM_AREA_TEE_RAM_RX:  core private read-only/executable memory (secure)
 * MEM_AREA_TEE_RAM_RO:  core private read-only/non-executable memory (secure)
 * MEM_AREA_TEE_RAM_RW:  core private read/write/non-executable memory (secure)
 * MEM_AREA_TEE_COHERENT: teecore coherent RAM (secure, reserved to TEE)
 * MEM_AREA_TA_RAM:   Secure RAM where teecore loads/exec TA instances.
 * MEM_AREA_NSEC_SHM: NonSecure shared RAM between NSec and TEE.
 * MEM_AREA_RAM_NSEC: NonSecure RAM storing data
 * MEM_AREA_RAM_SEC:  Secure RAM storing some secrets
 * MEM_AREA_IO_NSEC:  NonSecure HW mapped registers
 * MEM_AREA_IO_SEC:   Secure HW mapped registers
 * MEM_AREA_RES_VASPACE: Reserved virtual memory space
 * MEM_AREA_SHM_VASPACE: Virtual memory space for dynamic shared memory buffers
 * MEM_AREA_TA_VASPACE: TA va space, only used with phys_to_virt()
 * MEM_AREA_MAXTYPE:  lower invalid 'type' value
 */
enum teecore_memtypes {
	MEM_AREA_END = 0,
	MEM_AREA_TEE_RAM,
	MEM_AREA_TEE_RAM_RX,
	MEM_AREA_TEE_RAM_RO,
	MEM_AREA_TEE_RAM_RW,
	MEM_AREA_TEE_COHERENT,
	MEM_AREA_TA_RAM,
	MEM_AREA_NSEC_SHM,
	MEM_AREA_RAM_NSEC,
	MEM_AREA_RAM_SEC,
	MEM_AREA_IO_NSEC,
	MEM_AREA_IO_SEC,
	MEM_AREA_RES_VASPACE,
	MEM_AREA_SHM_VASPACE,
	MEM_AREA_TA_VASPACE,
	MEM_AREA_SDP_MEM,
	MEM_AREA_MAXTYPE
};

static inline const char *teecore_memtype_name(enum teecore_memtypes type)
{
	static const char * const names[] = {
		[MEM_AREA_END] = "END",
		[MEM_AREA_TEE_RAM] = "TEE_RAM_RWX",
		[MEM_AREA_TEE_RAM_RX] = "TEE_RAM_RX",
		[MEM_AREA_TEE_RAM_RO] = "TEE_RAM_RO",
		[MEM_AREA_TEE_RAM_RW] = "TEE_RAM_RW",
		[MEM_AREA_TEE_COHERENT] = "TEE_COHERENT",
		[MEM_AREA_TA_RAM] = "TA_RAM",
		[MEM_AREA_NSEC_SHM] = "NSEC_SHM",
		[MEM_AREA_RAM_NSEC] = "RAM_NSEC",
		[MEM_AREA_RAM_SEC] = "RAM_SEC",
		[MEM_AREA_IO_NSEC] = "IO_NSEC",
		[MEM_AREA_IO_SEC] = "IO_SEC",
		[MEM_AREA_RES_VASPACE] = "RES_VASPACE",
		[MEM_AREA_SHM_VASPACE] = "SHM_VASPACE",
		[MEM_AREA_TA_VASPACE] = "TA_VASPACE",
		[MEM_AREA_SDP_MEM] = "SDP_MEM",
	};

	COMPILE_TIME_ASSERT(ARRAY_SIZE(names) == MEM_AREA_MAXTYPE);
	return names[type];
}

#ifdef CFG_CORE_RWDATA_NOEXEC
#define MEM_AREA_TEE_RAM_RW_DATA	MEM_AREA_TEE_RAM_RW
#else
#define MEM_AREA_TEE_RAM_RW_DATA	MEM_AREA_TEE_RAM
#endif

struct core_mmu_phys_mem {
	const char *name;
	enum teecore_memtypes type;
	paddr_t addr;
	size_t size;
};

#define __register_memory2(_name, _type, _addr, _size, _section, _id) \
	static const struct core_mmu_phys_mem __phys_mem_ ## _id \
		__used __section(_section) = \
		{ .name = _name, .type = _type, .addr = _addr, .size = _size }

#define __register_memory1(name, type, addr, size, section, id) \
		__register_memory2(name, type, addr, size, #section, id)

#define register_phys_mem(type, addr, size) \
		__register_memory1(#addr, (type), (addr), (size), \
				   phys_mem_map_section, __COUNTER__)

#define register_sdp_mem(addr, size) \
		__register_memory1(#addr, MEM_AREA_SDP_MEM, (addr), (size), \
				   phys_sdp_mem_section, __COUNTER__)

#define register_nsec_ddr(addr, size) \
		__register_memory1(#addr, MEM_AREA_RAM_NSEC, (addr), (size), \
				   phys_nsec_ddr_section, __COUNTER__)

/* Default NSec shared memory allocated from NSec world */
extern unsigned long default_nsec_shm_paddr;
extern unsigned long default_nsec_shm_size;

void core_init_mmu_map(void);
void core_init_mmu_regs(void);

bool core_mmu_place_tee_ram_at_top(paddr_t paddr);

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
static inline bool core_mmu_user_va_range_is_defined(void)
{
	return true;
}
#endif

/*
 * core_mmu_get_user_va_range() - Return range of user va space
 * @base:	Lowest user virtual address
 * @size:	Size in bytes of user address space
 */
void core_mmu_get_user_va_range(vaddr_t *base, size_t *size);

/*
 * enum core_mmu_fault - different kinds of faults
 * @CORE_MMU_FAULT_ALIGNMENT:		alignment fault
 * @CORE_MMU_FAULT_DEBUG_EVENT:		debug event
 * @CORE_MMU_FAULT_TRANSLATION:		translation fault
 * @CORE_MMU_FAULT_WRITE_PERMISSION:	Permission fault during write
 * @CORE_MMU_FAULT_READ_PERMISSION:	Permission fault during read
 * @CORE_MMU_FAULT_ASYNC_EXTERNAL:	asynchronous external abort
 * @CORE_MMU_FAULT_ACCESS_BIT:		access bit fault
 * @CORE_MMU_FAULT_OTHER:		Other/unknown fault
 */
enum core_mmu_fault {
	CORE_MMU_FAULT_ALIGNMENT,
	CORE_MMU_FAULT_DEBUG_EVENT,
	CORE_MMU_FAULT_TRANSLATION,
	CORE_MMU_FAULT_WRITE_PERMISSION,
	CORE_MMU_FAULT_READ_PERMISSION,
	CORE_MMU_FAULT_ASYNC_EXTERNAL,
	CORE_MMU_FAULT_ACCESS_BIT,
	CORE_MMU_FAULT_OTHER,
};

/*
 * core_mmu_get_fault_type() - get fault type
 * @fault_descr:	Content of fault status or exception syndrome register
 * @returns an enum describing the content of fault status register.
 */
enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr);

/*
 * core_mm_type_to_attr() - convert memory type to attribute
 * @t: memory type
 * @returns an attribute that can be passed to core_mm_set_entry() and friends
 */
uint32_t core_mmu_type_to_attr(enum teecore_memtypes t);

/*
 * core_mmu_create_user_map() - Create user space mapping
 * @utc:	Pointer to user TA context
 * @map:	MMU configuration to use when activating this VA space
 */
void core_mmu_create_user_map(struct user_ta_ctx *utc,
			      struct core_mmu_user_map *map);
/*
 * core_mmu_get_user_map() - Reads current MMU configuration for user VA space
 * @map:	MMU configuration for current user VA space.
 */
void core_mmu_get_user_map(struct core_mmu_user_map *map);

/*
 * core_mmu_set_user_map() - Set new MMU configuration for user VA space
 * @map:	If NULL will disable user VA space, if not NULL the user
 *		VA space to activate.
 */
void core_mmu_set_user_map(struct core_mmu_user_map *map);

/*
 * struct core_mmu_table_info - Properties for a translation table
 * @table:	Pointer to translation table
 * @va_base:	VA base address of the transaltion table
 * @level:	Translation table level
 * @shift:	The shift of each entry in the table
 * @num_entries: Number of entries in this table.
 */
struct core_mmu_table_info {
	void *table;
	vaddr_t va_base;
	unsigned level;
	unsigned shift;
	unsigned num_entries;
};

/*
 * core_mmu_find_table() - Locates a translation table
 * @va:		Virtual address for the table to cover
 * @max_level:	Don't traverse beyond this level
 * @tbl_info:	Pointer to where to store properties.
 * @return true if a translation table was found, false on error
 */
bool core_mmu_find_table(vaddr_t va, unsigned max_level,
		struct core_mmu_table_info *tbl_info);

/*
 * core_mmu_divide_block() - divide larger block/section into smaller ones
 * @tbl_info:	table where target record located
 * @idx:	index of record
 * @return true if function was able to divide block, false on error
 */
bool core_mmu_divide_block(struct core_mmu_table_info *tbl_info,
			   unsigned int idx);

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr);

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info);

/*
 * core_mmu_set_entry() - Set entry in translation table
 * @tbl_info:	Translation table properties
 * @idx:	Index of entry to update
 * @pa:		Physical address to assign entry
 * @attr:	Attributes to assign entry
 */
void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t pa, uint32_t attr);

void core_mmu_get_entry_primitive(const void *table, size_t level, size_t idx,
				  paddr_t *pa, uint32_t *attr);

/*
 * core_mmu_get_entry() - Get entry from translation table
 * @tbl_info:	Translation table properties
 * @idx:	Index of entry to read
 * @pa:		Physical address is returned here if pa is not NULL
 * @attr:	Attributues are returned here if attr is not NULL
 */
void core_mmu_get_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
			paddr_t *pa, uint32_t *attr);

/*
 * core_mmu_va2idx() - Translate from virtual address to table index
 * @tbl_info:	Translation table properties
 * @va:		Virtual address to translate
 * @returns index in transaltion table
 */
static inline unsigned core_mmu_va2idx(struct core_mmu_table_info *tbl_info,
			vaddr_t va)
{
	return (va - tbl_info->va_base) >> tbl_info->shift;
}

/*
 * core_mmu_idx2va() - Translate from table index to virtual address
 * @tbl_info:	Translation table properties
 * @idx:	Index to translate
 * @returns Virtual address
 */
static inline vaddr_t core_mmu_idx2va(struct core_mmu_table_info *tbl_info,
			unsigned idx)
{
	return (idx << tbl_info->shift) + tbl_info->va_base;
}

/*
 * core_mmu_get_block_offset() - Get offset inside a block/page
 * @tbl_info:	Translation table properties
 * @pa:		Physical address
 * @returns offset within one block of the translation table
 */
static inline size_t core_mmu_get_block_offset(
			struct core_mmu_table_info *tbl_info, paddr_t pa)
{
	return pa & ((1 << tbl_info->shift) - 1);
}

/*
 * core_mmu_is_dynamic_vaspace() - Check if memory region belongs to
 *  empty virtual address space that is used for dymanic mappings
 * @mm:		memory region to be checked
 * @returns result of the check
 */
static inline bool core_mmu_is_dynamic_vaspace(struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_RES_VASPACE ||
		mm->type == MEM_AREA_SHM_VASPACE;
}

/*
 * core_mmu_map_pages() - map list of pages at given virtual address
 * @vstart:	Virtual address where mapping begins
 * @pages:	Array of page addresses
 * @num_pages:	Number of pages
 * @memtype:	Type of memmory to be mapped
 * @returns:	TEE_SUCCESS on success, TEE_ERROR_XXX on error
 */
TEE_Result core_mmu_map_pages(vaddr_t vstart, paddr_t *pages, size_t num_pages,
			      enum teecore_memtypes memtype);

/*
 * core_mmu_unmap_pages() - remove mapping at given virtual address
 * @vstart:	Virtual address where mapping begins
 * @num_pages:	Number of pages to unmap
 */
void core_mmu_unmap_pages(vaddr_t vstart, size_t num_pages);

/*
 * core_mmu_user_mapping_is_active() - Report if user mapping is active
 * @returns true if a user VA space is active, false if user VA space is
 *          inactive.
 */
bool core_mmu_user_mapping_is_active(void);

/*
 * core_mmu_mattr_is_ok() - Check that supplied mem attributes can be used
 * @returns true if the attributes can be used, false if not.
 */
bool core_mmu_mattr_is_ok(uint32_t mattr);

void core_mmu_get_mem_by_type(enum teecore_memtypes type, vaddr_t *s,
			      vaddr_t *e);

enum teecore_memtypes core_mmu_get_type_by_pa(paddr_t pa);

/* routines to retreive shared mem configuration */
static inline bool core_mmu_is_shm_cached(void)
{
	return core_mmu_type_to_attr(MEM_AREA_NSEC_SHM) &
		(TEE_MATTR_CACHE_CACHED << TEE_MATTR_CACHE_SHIFT);
}

bool core_mmu_add_mapping(enum teecore_memtypes type, paddr_t addr, size_t len);

/* various invalidate secure TLB */
enum teecore_tlb_op {
	TLBINV_UNIFIEDTLB,	/* invalidate unified tlb */
	TLBINV_CURRENT_ASID,	/* invalidate unified tlb for current ASID */
	TLBINV_BY_ASID,		/* invalidate unified tlb by ASID */
	TLBINV_BY_MVA,		/* invalidate unified tlb by MVA */
};

/* TLB invalidation for a range of virtual address */
void tlbi_mva_range(vaddr_t va, size_t size, size_t granule);

/* deprecated: please call straight tlbi_all() and friends */
int core_tlb_maintenance(int op, unsigned long a) __deprecated;

/* Cache maintenance operation type (deprecated with core_tlb_maintenance()) */
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

/* Check cpu mmu enabled or not */
bool cpu_mmu_enabled(void);

/*
 * Check if platform defines nsec DDR range(s).
 * Static SHM (MEM_AREA_NSEC_SHM) is not covered by this API as it is
 * always present.
 */
bool core_mmu_nsec_ddr_is_defined(void);

#ifdef CFG_DT
void core_mmu_set_discovered_nsec_ddr(struct core_mmu_phys_mem *start,
				      size_t nelems);
#endif

#ifdef CFG_SECURE_DATA_PATH
/* Alloc and fill SDP memory objects table - table is NULL terminated */
struct mobj **core_sdp_mem_create_mobjs(void);
#endif

#endif /* CORE_MMU_H */
