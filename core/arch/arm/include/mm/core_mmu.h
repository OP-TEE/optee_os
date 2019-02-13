/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef CORE_MMU_H
#define CORE_MMU_H

#ifndef ASM
#include <assert.h>
#include <compiler.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <platform_config.h>

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
#define CORE_MMU_PGDIR_LEVEL	3
#else
#define CORE_MMU_PGDIR_SHIFT	20
#define CORE_MMU_PGDIR_LEVEL	2
#endif
#define CORE_MMU_PGDIR_SIZE		(1 << CORE_MMU_PGDIR_SHIFT)
#define CORE_MMU_PGDIR_MASK		(CORE_MMU_PGDIR_SIZE - 1)

/* TA user space code, data, stack and heap are mapped using this granularity */
#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_CODE_SIZE		(1 << CORE_MMU_USER_CODE_SHIFT)
#define CORE_MMU_USER_CODE_MASK		(CORE_MMU_USER_CODE_SIZE - 1)

/* TA user space parameters are mapped using this granularity */
#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT
#define CORE_MMU_USER_PARAM_SIZE	(1 << CORE_MMU_USER_PARAM_SHIFT)
#define CORE_MMU_USER_PARAM_MASK	(CORE_MMU_USER_PARAM_SIZE - 1)

/*
 * CORE_MMU_L1_TBL_OFFSET is used when switching to/from reduced kernel
 * mapping. The actual value depends on internals in core_mmu_lpae.c and
 * core_mmu_v7.c which we rather not expose here. There's a compile time
 * assertion to check that these magic numbers are correct.
 */
#ifdef CFG_WITH_LPAE
#define CORE_MMU_L1_TBL_OFFSET		(CFG_TEE_CORE_NB_CORE * 4 * 8)
#else
#define CORE_MMU_L1_TBL_OFFSET		(4096 * 4)
#endif
/*
 * TEE_RAM_VA_START:            The start virtual address of the TEE RAM
 * TEE_TEXT_VA_START:           The start virtual address of the OP-TEE text
 */

/*
 * Identify mapping constraint: virtual base address is the physical start addr.
 * If platform did not set some macros, some get default value.
 */
#ifndef TEE_RAM_VA_SIZE
#define TEE_RAM_VA_SIZE			CORE_MMU_PGDIR_SIZE
#endif

#ifndef TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#define TEE_RAM_VA_START		TEE_RAM_START
#define TEE_TEXT_VA_START		(TEE_RAM_VA_START + \
					 (TEE_LOAD_ADDR - TEE_RAM_START))

#ifndef STACK_ALIGNMENT
#define STACK_ALIGNMENT			(sizeof(long) * 2)
#endif

#ifndef ASM
/*
 * Memory area type:
 * MEM_AREA_END:      Reserved, marks the end of a table of mapping areas.
 * MEM_AREA_TEE_RAM:  core RAM (read/write/executable, secure, reserved to TEE)
 * MEM_AREA_TEE_RAM_RX:  core private read-only/executable memory (secure)
 * MEM_AREA_TEE_RAM_RO:  core private read-only/non-executable memory (secure)
 * MEM_AREA_TEE_RAM_RW:  core private read/write/non-executable memory (secure)
 * MEM_AREA_NEX_RAM_RW: nexus private r/w/non-executable memory (secure)
 * MEM_AREA_TEE_COHERENT: teecore coherent RAM (secure, reserved to TEE)
 * MEM_AREA_TEE_ASAN: core address sanitizer RAM (secure, reserved to TEE)
 * MEM_AREA_TA_RAM:   Secure RAM where teecore loads/exec TA instances.
 * MEM_AREA_NSEC_SHM: NonSecure shared RAM between NSec and TEE.
 * MEM_AREA_RAM_NSEC: NonSecure RAM storing data
 * MEM_AREA_RAM_SEC:  Secure RAM storing some secrets
 * MEM_AREA_IO_NSEC:  NonSecure HW mapped registers
 * MEM_AREA_IO_SEC:   Secure HW mapped registers
 * MEM_AREA_RES_VASPACE: Reserved virtual memory space
 * MEM_AREA_SHM_VASPACE: Virtual memory space for dynamic shared memory buffers
 * MEM_AREA_TA_VASPACE: TA va space, only used with phys_to_virt()
 * MEM_AREA_DDR_OVERALL: Overall DDR address range, candidate to dynamic shm.
 * MEM_AREA_SEC_RAM_OVERALL: Whole secure RAM
 * MEM_AREA_MAXTYPE:  lower invalid 'type' value
 */
enum teecore_memtypes {
	MEM_AREA_END = 0,
	MEM_AREA_TEE_RAM,
	MEM_AREA_TEE_RAM_RX,
	MEM_AREA_TEE_RAM_RO,
	MEM_AREA_TEE_RAM_RW,
	MEM_AREA_NEX_RAM_RW,
	MEM_AREA_TEE_COHERENT,
	MEM_AREA_TEE_ASAN,
	MEM_AREA_TA_RAM,
	MEM_AREA_NSEC_SHM,
	MEM_AREA_RAM_NSEC,
	MEM_AREA_RAM_SEC,
	MEM_AREA_IO_NSEC,
	MEM_AREA_IO_SEC,
	MEM_AREA_RES_VASPACE,
	MEM_AREA_SHM_VASPACE,
	MEM_AREA_TA_VASPACE,
	MEM_AREA_PAGER_VASPACE,
	MEM_AREA_SDP_MEM,
	MEM_AREA_DDR_OVERALL,
	MEM_AREA_SEC_RAM_OVERALL,
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
		[MEM_AREA_NEX_RAM_RW] = "NEX_RAM_RW",
		[MEM_AREA_TEE_ASAN] = "TEE_ASAN",
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
		[MEM_AREA_PAGER_VASPACE] = "PAGER_VASPACE",
		[MEM_AREA_SDP_MEM] = "SDP_MEM",
		[MEM_AREA_DDR_OVERALL] = "DDR_OVERALL",
		[MEM_AREA_SEC_RAM_OVERALL] = "SEC_RAM_OVERALL",
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
	__extension__ union {
#if __SIZEOF_LONG__ != __SIZEOF_PADDR__
		struct {
			uint32_t lo_addr;
			uint32_t hi_addr;
		};
#endif
		paddr_t addr;
	};
	__extension__ union {
#if __SIZEOF_LONG__ != __SIZEOF_PADDR__
		struct {
			uint32_t lo_size;
			uint32_t hi_size;
		};
#endif
		paddr_size_t size;
	};
};

#define __register_memory(_name, _type, _addr, _size, _section) \
	SCATTERED_ARRAY_DEFINE_ITEM(_section, struct core_mmu_phys_mem) = \
		{ .name = (_name), .type = (_type), .addr = (_addr), \
		  .size = (_size) }

#if __SIZEOF_LONG__ != __SIZEOF_PADDR__
#define __register_memory_ul(_name, _type, _addr, _size, _section) \
	SCATTERED_ARRAY_DEFINE_ITEM(_section, struct core_mmu_phys_mem) = \
		{ .name = (_name), .type = (_type), .lo_addr = (_addr), \
		  .lo_size = (_size) }
#else
#define __register_memory_ul(_name, _type, _addr, _size, _section) \
		__register_memory(_name, _type, _addr, _size, _section)
#endif

#define register_phys_mem(type, addr, size) \
		__register_memory(#addr, (type), (addr), (size), \
				  phys_mem_map)

#define register_phys_mem_ul(type, addr, size) \
		__register_memory_ul(#addr, (type), (addr), (size), \
				     phys_mem_map)

/* Same as register_phys_mem() but with PGDIR_SIZE granularity */
#define register_phys_mem_pgdir(type, addr, size) \
	register_phys_mem(type, ROUNDDOWN(addr, CORE_MMU_PGDIR_SIZE), \
		ROUNDUP(size + addr - ROUNDDOWN(addr, CORE_MMU_PGDIR_SIZE), \
			CORE_MMU_PGDIR_SIZE))

#ifdef CFG_SECURE_DATA_PATH
#define register_sdp_mem(addr, size) \
		__register_memory(#addr, MEM_AREA_SDP_MEM, (addr), (size), \
				  phys_sdp_mem)
#else
#define register_sdp_mem(addr, size) \
		static int CONCAT(__register_sdp_mem_unused, __COUNTER__) \
			__unused
#endif

#define register_dynamic_shm(addr, size) \
		__register_memory(#addr, MEM_AREA_RAM_NSEC, (addr), (size), \
				  phys_nsec_ddr)

#define register_ddr(addr, size) \
		__register_memory(#addr, MEM_AREA_DDR_OVERALL, (addr), \
				  (size), phys_ddr_overall)

#define phys_ddr_overall_begin \
	SCATTERED_ARRAY_BEGIN(phys_ddr_overall, struct core_mmu_phys_mem)

#define phys_ddr_overall_end \
	SCATTERED_ARRAY_END(phys_ddr_overall, struct core_mmu_phys_mem)

#define phys_nsec_ddr_begin \
	SCATTERED_ARRAY_BEGIN(phys_nsec_ddr, struct core_mmu_phys_mem)

#define phys_nsec_ddr_end \
	SCATTERED_ARRAY_END(phys_nsec_ddr, struct core_mmu_phys_mem)

#define phys_sdp_mem_begin \
	SCATTERED_ARRAY_BEGIN(phys_sdp_mem, struct core_mmu_phys_mem)

#define phys_sdp_mem_end \
	SCATTERED_ARRAY_END(phys_sdp_mem, struct core_mmu_phys_mem)

#define phys_mem_map_begin \
	SCATTERED_ARRAY_BEGIN(phys_mem_map, struct core_mmu_phys_mem)

#define phys_mem_map_end \
	SCATTERED_ARRAY_END(phys_mem_map, struct core_mmu_phys_mem)

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
 * struct mmu_partition - stores MMU partition.
 *
 * Basically it	represent whole MMU mapping. It is possible
 * to create multiple partitions, and change them in runtime,
 * effectively changing how OP-TEE sees memory.
 * This is opaque struct which is defined differently for
 * v7 and LPAE MMUs
 *
 * This structure used mostly when virtualization is enabled.
 * When CFG_VIRTUALIZATION==n only default partition exists.
 */
struct mmu_partition;

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
#ifdef CFG_VIRTUALIZATION
	struct mmu_partition *prtn;
#endif
};

/*
 * core_mmu_find_table() - Locates a translation table
 * @prtn:	MMU partition where search should be performed
 * @va:		Virtual address for the table to cover
 * @max_level:	Don't traverse beyond this level
 * @tbl_info:	Pointer to where to store properties.
 * @return true if a translation table was found, false on error
 */
bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned max_level,
			 struct core_mmu_table_info *tbl_info);

/*
 * core_mmu_entry_to_finer_grained() - divide mapping at current level into
 *     smaller ones so memory can be mapped with finer granularity
 * @tbl_info:	table where target record located
 * @idx:	index of record for which a pdgir must be setup.
 * @secure:	true/false if pgdir maps secure/non-secure memory (32bit mmu)
 * @return true on successful, false on error
 */
bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure);

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

/* Do section mapping, not support on LPAE */
void map_memarea_sections(const struct tee_mmap_region *mm, uint32_t *ttb);

/*
 * Check if platform defines nsec DDR range(s).
 * Static SHM (MEM_AREA_NSEC_SHM) is not covered by this API as it is
 * always present.
 */
bool core_mmu_nsec_ddr_is_defined(void);

void core_mmu_set_discovered_nsec_ddr(struct core_mmu_phys_mem *start,
				      size_t nelems);

/* Initialize MMU partition */
void core_init_mmu_prtn(struct mmu_partition *prtn, struct tee_mmap_region *mm);

unsigned int asid_alloc(void);
void asid_free(unsigned int asid);

#ifdef CFG_SECURE_DATA_PATH
/* Alloc and fill SDP memory objects table - table is NULL terminated */
struct mobj **core_sdp_mem_create_mobjs(void);
#endif

#ifdef CFG_VIRTUALIZATION
size_t core_mmu_get_total_pages_size(void);
struct mmu_partition *core_alloc_mmu_prtn(void *tables);
void core_free_mmu_prtn(struct mmu_partition *prtn);
void core_mmu_set_prtn(struct mmu_partition *prtn);
void core_mmu_set_default_prtn(void);

void core_mmu_init_virtualization(void);
#endif

#endif /*ASM*/

#endif /* CORE_MMU_H */
