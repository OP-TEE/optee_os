/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __MM_CORE_MMU_H
#define __MM_CORE_MMU_H

#ifndef __ASSEMBLER__
#include <assert.h>
#include <compiler.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <mm/core_mmu_arch.h>
#include <platform_config.h>

/* A small page is the smallest unit of memory that can be mapped */
#define SMALL_PAGE_SIZE			BIT(SMALL_PAGE_SHIFT)
#define SMALL_PAGE_MASK			((paddr_t)SMALL_PAGE_SIZE - 1)

/*
 * PGDIR is the translation table above the translation table that holds
 * the pages.
 */
#define CORE_MMU_PGDIR_SIZE		BIT(CORE_MMU_PGDIR_SHIFT)
#define CORE_MMU_PGDIR_MASK		((paddr_t)CORE_MMU_PGDIR_SIZE - 1)

/* TA user space code, data, stack and heap are mapped using this granularity */
#define CORE_MMU_USER_CODE_SIZE		BIT(CORE_MMU_USER_CODE_SHIFT)
#define CORE_MMU_USER_CODE_MASK		((paddr_t)CORE_MMU_USER_CODE_SIZE - 1)

/* TA user space parameters are mapped using this granularity */
#define CORE_MMU_USER_PARAM_SIZE	BIT(CORE_MMU_USER_PARAM_SHIFT)
#define CORE_MMU_USER_PARAM_MASK	((paddr_t)CORE_MMU_USER_PARAM_SIZE - 1)

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

#ifndef STACK_ALIGNMENT
#define STACK_ALIGNMENT			(sizeof(long) * U(2))
#endif

#ifndef __ASSEMBLER__
/*
 * Memory area type:
 * MEM_AREA_END:      Reserved, marks the end of a table of mapping areas.
 * MEM_AREA_TEE_RAM:  core RAM (read/write/executable, secure, reserved to TEE)
 * MEM_AREA_TEE_RAM_RX:  core private read-only/executable memory (secure)
 * MEM_AREA_TEE_RAM_RO:  core private read-only/non-executable memory (secure)
 * MEM_AREA_TEE_RAM_RW:  core private read/write/non-executable memory (secure)
 * MEM_AREA_INIT_RAM_RO: init private read-only/non-executable memory (secure)
 * MEM_AREA_INIT_RAM_RX: init private read-only/executable memory (secure)
 * MEM_AREA_NEX_RAM_RO: nexus private read-only/non-executable memory (secure)
 * MEM_AREA_NEX_RAM_RW: nexus private r/w/non-executable memory (secure)
 * MEM_AREA_TEE_COHERENT: teecore coherent RAM (secure, reserved to TEE)
 * MEM_AREA_TEE_ASAN: core address sanitizer RAM (secure, reserved to TEE)
 * MEM_AREA_IDENTITY_MAP_RX: core identity mapped r/o executable memory (secure)
 * MEM_AREA_TA_RAM:   Secure RAM where teecore loads/exec TA instances.
 * MEM_AREA_NSEC_SHM: NonSecure shared RAM between NSec and TEE.
 * MEM_AREA_NEX_NSEC_SHM: nexus non-secure shared RAM between NSec and TEE.
 * MEM_AREA_RAM_NSEC: NonSecure RAM storing data
 * MEM_AREA_RAM_SEC:  Secure RAM storing some secrets
 * MEM_AREA_ROM_SEC:  Secure read only memory storing some secrets
 * MEM_AREA_IO_NSEC:  NonSecure HW mapped registers
 * MEM_AREA_IO_SEC:   Secure HW mapped registers
 * MEM_AREA_EXT_DT:   Memory loads external device tree
 * MEM_AREA_MANIFEST_DT: Memory loads manifest device tree
 * MEM_AREA_TRANSFER_LIST: Memory area mapped for Transfer List
 * MEM_AREA_RES_VASPACE: Reserved virtual memory space
 * MEM_AREA_SHM_VASPACE: Virtual memory space for dynamic shared memory buffers
 * MEM_AREA_TS_VASPACE: TS va space, only used with phys_to_virt()
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
	MEM_AREA_INIT_RAM_RO,
	MEM_AREA_INIT_RAM_RX,
	MEM_AREA_NEX_RAM_RO,
	MEM_AREA_NEX_RAM_RW,
	MEM_AREA_TEE_COHERENT,
	MEM_AREA_TEE_ASAN,
	MEM_AREA_IDENTITY_MAP_RX,
	MEM_AREA_TA_RAM,
	MEM_AREA_NSEC_SHM,
	MEM_AREA_NEX_NSEC_SHM,
	MEM_AREA_RAM_NSEC,
	MEM_AREA_RAM_SEC,
	MEM_AREA_ROM_SEC,
	MEM_AREA_IO_NSEC,
	MEM_AREA_IO_SEC,
	MEM_AREA_EXT_DT,
	MEM_AREA_MANIFEST_DT,
	MEM_AREA_TRANSFER_LIST,
	MEM_AREA_RES_VASPACE,
	MEM_AREA_SHM_VASPACE,
	MEM_AREA_TS_VASPACE,
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
		[MEM_AREA_INIT_RAM_RO] = "INIT_RAM_RO",
		[MEM_AREA_INIT_RAM_RX] = "INIT_RAM_RX",
		[MEM_AREA_NEX_RAM_RO] = "NEX_RAM_RO",
		[MEM_AREA_NEX_RAM_RW] = "NEX_RAM_RW",
		[MEM_AREA_TEE_ASAN] = "TEE_ASAN",
		[MEM_AREA_IDENTITY_MAP_RX] = "IDENTITY_MAP_RX",
		[MEM_AREA_TEE_COHERENT] = "TEE_COHERENT",
		[MEM_AREA_TA_RAM] = "TA_RAM",
		[MEM_AREA_NSEC_SHM] = "NSEC_SHM",
		[MEM_AREA_NEX_NSEC_SHM] = "NEX_NSEC_SHM",
		[MEM_AREA_RAM_NSEC] = "RAM_NSEC",
		[MEM_AREA_RAM_SEC] = "RAM_SEC",
		[MEM_AREA_ROM_SEC] = "ROM_SEC",
		[MEM_AREA_IO_NSEC] = "IO_NSEC",
		[MEM_AREA_IO_SEC] = "IO_SEC",
		[MEM_AREA_EXT_DT] = "EXT_DT",
		[MEM_AREA_MANIFEST_DT] = "MANIFEST_DT",
		[MEM_AREA_TRANSFER_LIST] = "TRANSFER_LIST",
		[MEM_AREA_RES_VASPACE] = "RES_VASPACE",
		[MEM_AREA_SHM_VASPACE] = "SHM_VASPACE",
		[MEM_AREA_TS_VASPACE] = "TS_VASPACE",
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
	__register_memory(#addr, type, ROUNDDOWN(addr, CORE_MMU_PGDIR_SIZE), \
			  ROUNDUP(size + addr - \
					ROUNDDOWN(addr, CORE_MMU_PGDIR_SIZE), \
				  CORE_MMU_PGDIR_SIZE), phys_mem_map)

#ifdef CFG_SECURE_DATA_PATH
#define register_sdp_mem(addr, size) \
		__register_memory(#addr, MEM_AREA_SDP_MEM, (addr), (size), \
				  phys_sdp_mem)
#else
#define register_sdp_mem(addr, size) \
		static int CONCAT(__register_sdp_mem_unused, __COUNTER__) \
			__unused
#endif

/* register_dynamic_shm() is deprecated, please use register_ddr() instead */
#define register_dynamic_shm(addr, size) \
		__register_memory(#addr, MEM_AREA_DDR_OVERALL, (addr), (size), \
				  phys_ddr_overall_compat)

/*
 * register_ddr() - Define a memory range
 * @addr: Base address
 * @size: Length
 *
 * This macro can be used multiple times to define disjoint ranges. While
 * initializing holes are carved out of these ranges where it overlaps with
 * special memory, for instance memory registered with register_sdp_mem().
 *
 * The memory that remains is accepted as non-secure shared memory when
 * communicating with normal world.
 *
 * This macro is an alternative to supply the memory description with a
 * devicetree blob.
 */
#define register_ddr(addr, size) \
		__register_memory(#addr, MEM_AREA_DDR_OVERALL, (addr), \
				  (size), phys_ddr_overall)

#define phys_ddr_overall_begin \
	SCATTERED_ARRAY_BEGIN(phys_ddr_overall, struct core_mmu_phys_mem)

#define phys_ddr_overall_end \
	SCATTERED_ARRAY_END(phys_ddr_overall, struct core_mmu_phys_mem)

#define phys_ddr_overall_compat_begin \
	SCATTERED_ARRAY_BEGIN(phys_ddr_overall_compat, struct core_mmu_phys_mem)

#define phys_ddr_overall_compat_end \
	SCATTERED_ARRAY_END(phys_ddr_overall_compat, struct core_mmu_phys_mem)

#define phys_sdp_mem_begin \
	SCATTERED_ARRAY_BEGIN(phys_sdp_mem, struct core_mmu_phys_mem)

#define phys_sdp_mem_end \
	SCATTERED_ARRAY_END(phys_sdp_mem, struct core_mmu_phys_mem)

#define phys_mem_map_begin \
	SCATTERED_ARRAY_BEGIN(phys_mem_map, struct core_mmu_phys_mem)

#define phys_mem_map_end \
	SCATTERED_ARRAY_END(phys_mem_map, struct core_mmu_phys_mem)

#ifdef CFG_CORE_RESERVED_SHM
/* Default NSec shared memory allocated from NSec world */
extern unsigned long default_nsec_shm_paddr;
extern unsigned long default_nsec_shm_size;
#endif

/*
 * Physical load address of OP-TEE updated during boot if needed to reflect
 * the value used.
 */
#ifdef CFG_CORE_PHYS_RELOCATABLE
extern unsigned long core_mmu_tee_load_pa;
#else
extern const unsigned long core_mmu_tee_load_pa;
#endif

void core_init_mmu_map(unsigned long seed, struct core_mmu_config *cfg);
void core_init_mmu_regs(struct core_mmu_config *cfg);

/* Arch specific function to help optimizing 1 MMU xlat table */
bool core_mmu_prefer_tee_ram_at_top(paddr_t paddr);

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
 * When CFG_NS_VIRTUALIZATION==n only default partition exists.
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
 * @CORE_MMU_FAULT_TAG_CHECK:		tag check fault
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
	CORE_MMU_FAULT_TAG_CHECK,
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
 * core_mmu_create_user_map() - Create user mode mapping
 * @uctx:	Pointer to user mode context
 * @map:	MMU configuration to use when activating this VA space
 */
void core_mmu_create_user_map(struct user_mode_ctx *uctx,
			      struct core_mmu_user_map *map);
/*
 * core_mmu_get_user_map() - Reads current MMU configuration for user VA space
 * @map:	MMU configuration for current user VA space.
 */
void core_mmu_get_user_map(struct core_mmu_user_map *map);

/*
 * core_mmu_set_user_map() - Set new MMU configuration for user VA space
 * @map:	User context MMU configuration or NULL to set core VA space
 *
 * Activate user VA space mapping and set its ASID if @map is not NULL,
 * otherwise activate core mapping and set ASID to 0.
 */
void core_mmu_set_user_map(struct core_mmu_user_map *map);

/*
 * struct core_mmu_table_info - Properties for a translation table
 * @table:	Pointer to translation table
 * @va_base:	VA base address of the transaltion table
 * @level:	Translation table level
 * @next_level:	Finer grained translation table level according to @level.
 * @shift:	The shift of each entry in the table
 * @num_entries: Number of entries in this table.
 */
struct core_mmu_table_info {
	void *table;
	vaddr_t va_base;
	unsigned num_entries;
#ifdef CFG_NS_VIRTUALIZATION
	struct mmu_partition *prtn;
#endif
	uint8_t level;
	uint8_t shift;
	uint8_t next_level;
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
 *
 * Note: This function asserts that pages are not mapped executeable for
 * kernel (privileged) mode.
 *
 * @returns:	TEE_SUCCESS on success, TEE_ERROR_XXX on error
 */
TEE_Result core_mmu_map_pages(vaddr_t vstart, paddr_t *pages, size_t num_pages,
			      enum teecore_memtypes memtype);

/*
 * core_mmu_map_contiguous_pages() - map range of pages at given virtual address
 * @vstart:	Virtual address where mapping begins
 * @pstart:	Physical address of the first page
 * @num_pages:	Number of pages
 * @memtype:	Type of memmory to be mapped
 *
 * Note: This function asserts that pages are not mapped executeable for
 * kernel (privileged) mode.
 *
 * @returns:	TEE_SUCCESS on success, TEE_ERROR_XXX on error
 */
TEE_Result core_mmu_map_contiguous_pages(vaddr_t vstart, paddr_t pstart,
					 size_t num_pages,
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
	return mattr_is_cached(core_mmu_type_to_attr(MEM_AREA_NSEC_SHM));
}

TEE_Result core_mmu_remove_mapping(enum teecore_memtypes type, void *addr,
				   size_t len);
void *core_mmu_add_mapping(enum teecore_memtypes type, paddr_t addr,
			   size_t len);

/*
 * core_mmu_find_mapping_exclusive() - Find mapping of specified type and
 *				       length. If more than one mapping of
 *				       specified type is present, NULL will be
 *				       returned.
 * @type:	memory type
 * @len:	length in bytes
 */
struct tee_mmap_region *
core_mmu_find_mapping_exclusive(enum teecore_memtypes type, size_t len);

/*
 * tlbi_va_range() - Invalidate TLB for virtual address range
 * @va:		start virtual address, must be a multiple of @granule
 * @len:	length in bytes of range, must be a multiple of @granule
 * @granule:	granularity of mapping, supported values are
 *		CORE_MMU_PGDIR_SIZE or SMALL_PAGE_SIZE. This value must
 *		match the actual mappings.
 */
void tlbi_va_range(vaddr_t va, size_t len, size_t granule);

/*
 * tlbi_va_range_asid() - Invalidate TLB for virtual address range for
 *			  a specific ASID
 * @va:		start virtual address, must be a multiple of @granule
 * @len:	length in bytes of range, must be a multiple of @granule
 * @granule:	granularity of mapping, supported values are
 *		CORE_MMU_PGDIR_SIZE or SMALL_PAGE_SIZE. This value must
 *		match the actual mappings.
 * @asid:	Address space identifier
 */
void tlbi_va_range_asid(vaddr_t va, size_t len, size_t granule, uint32_t asid);

/* Check cpu mmu enabled or not */
bool cpu_mmu_enabled(void);

#ifdef CFG_CORE_DYN_SHM
/*
 * Check if platform defines nsec DDR range(s).
 * Static SHM (MEM_AREA_NSEC_SHM) is not covered by this API as it is
 * always present.
 */
bool core_mmu_nsec_ddr_is_defined(void);

void core_mmu_set_discovered_nsec_ddr(struct core_mmu_phys_mem *start,
				      size_t nelems);
#endif

/* Initialize MMU partition */
void core_init_mmu_prtn(struct mmu_partition *prtn, struct tee_mmap_region *mm);

unsigned int asid_alloc(void);
void asid_free(unsigned int asid);

#ifdef CFG_SECURE_DATA_PATH
/* Alloc and fill SDP memory objects table - table is NULL terminated */
struct mobj **core_sdp_mem_create_mobjs(void);
#endif

#ifdef CFG_NS_VIRTUALIZATION
size_t core_mmu_get_total_pages_size(void);
struct mmu_partition *core_alloc_mmu_prtn(void *tables);
void core_free_mmu_prtn(struct mmu_partition *prtn);
void core_mmu_set_prtn(struct mmu_partition *prtn);
void core_mmu_set_default_prtn(void);
void core_mmu_set_default_prtn_tbl(void);
#endif

void core_mmu_init_virtualization(void);

/* init some allocation pools */
void core_mmu_init_ta_ram(void);

void core_init_mmu(struct tee_mmap_region *mm);

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
			     unsigned int level, vaddr_t va_base, void *table);
void core_mmu_populate_user_map(struct core_mmu_table_info *dir_info,
				struct user_mode_ctx *uctx);
void core_mmu_map_region(struct mmu_partition *prtn,
			 struct tee_mmap_region *mm);

bool arch_va2pa_helper(void *va, paddr_t *pa);

static inline bool core_mmap_is_end_of_table(const struct tee_mmap_region *mm)
{
	return mm->type == MEM_AREA_END;
}

static inline bool core_mmu_check_end_pa(paddr_t pa, size_t len)
{
	paddr_t end_pa = 0;

	if (ADD_OVERFLOW(pa, len - 1, &end_pa))
		return false;
	return core_mmu_check_max_pa(end_pa);
}

/*
 * core_mmu_set_secure_memory() - set physical secure memory range
 * @base: base address of secure memory
 * @size: size of secure memory
 *
 * The physical secure memory range is not known in advance when OP-TEE is
 * relocatable, this information must be supplied once during boot before
 * the translation tables can be initialized and the MMU enabled.
 */
void core_mmu_set_secure_memory(paddr_t base, size_t size);

/*
 * core_mmu_get_secure_memory() - get physical secure memory range
 * @base: base address of secure memory
 * @size: size of secure memory
 *
 * The physical secure memory range returned covers at least the memory
 * range used by OP-TEE Core, but may cover more memory depending on the
 * configuration.
 */
void core_mmu_get_secure_memory(paddr_t *base, paddr_size_t *size);

/*
 * core_mmu_get_ta_range() - get physical memory range reserved for TAs
 * @base: [out] range base address ref or NULL
 * @size: [out] range size ref or NULL
 */
void core_mmu_get_ta_range(paddr_t *base, size_t *size);

#endif /*__ASSEMBLER__*/

#endif /* __MM_CORE_MMU_H */
