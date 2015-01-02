/*
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

#include <types_ext.h>
#include <kernel/tee_common_unpg.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu_types.h>

#include <assert.h>

/*
 * PGDIR is the translation table above the translation table that holds
 * the pages.
 */
#ifdef CFG_WITH_LPAE
#define CORE_MMU_PGDIR_SHIFT	21
#else
#define CORE_MMU_PGDIR_SHIFT	20
#endif

/* Devices are mapped using this granularity */
#define CORE_MMU_DEVICE_SHIFT		CORE_MMU_PGDIR_SHIFT
#define CORE_MMU_DEVICE_SIZE		(1 << CORE_MMU_DEVICE_SHIFT)
#define CORE_MMU_DEVICE_MASK		(CORE_MMU_DEVICE_SIZE - 1)

/* TA user space code, data, stack and heap are mapped using this granularity */
#define CORE_MMU_USER_CODE_SHIFT	CORE_MMU_PGDIR_SHIFT
#define CORE_MMU_USER_CODE_SIZE		(1 << CORE_MMU_USER_CODE_SHIFT)
#define CORE_MMU_USER_CODE_MASK		(CORE_MMU_USER_CODE_SIZE - 1)

/* TA user space parameters are mapped using this granularity */
#define CORE_MMU_USER_PARAM_SHIFT	CORE_MMU_PGDIR_SHIFT
#define CORE_MMU_USER_PARAM_SIZE	(1 << CORE_MMU_USER_PARAM_SHIFT)
#define CORE_MMU_USER_PARAM_MASK	(CORE_MMU_USER_PARAM_SIZE - 1)

/* The maximum VA for user space */
#define CORE_MMU_USER_MAX_ADDR	(32 * 1024 * 1024)

/*
 * @type:  enumerate: specifiy the purpose of the memory area.
 * @pa:    memory area physical start address
 * @size:  memory area size in bytes
 * @va:    virtual start address (0 if memory is not mapped)
 * @region_size: size of the mapping region used (4k, 64K, 1MB)
 * @secure: true if memory area in inside a A9 secure area
 */
struct map_area {
	unsigned int type;
	unsigned int pa;
	size_t size;
	/* below here are core_mmu.c internal data */
	unsigned int va;
	unsigned int region_size;
	bool secure;
	bool cached;
	bool device;
	bool rw;
	bool exec;
};

/*
 * Memory area type:
 * MEM_AREA_NOTYPE:   Undefined type. Used as end of table.
 * MEM_AREA_TEE_RAM:  teecore execution RAM (secure, reserved to TEEtz, unused)
 * MEM_AREA_TEE_COHERENT: teecore coherent RAM (secure, reserved to TEEtz)
 * MEM_AREA_TA_RAM:   Secure RAM where teecore loads/exec TA instances.
 * MEM_AREA_NS_SHM:   NonSecure shared RAM between NSec and TEEtz.
 * MEM_AREA_KEYVAULT: Secure RAM storing some secrets
 * MEM_AREA_IO_SEC:   Secure HW mapped registers
 * MEM_AREA_IO_NSEC:  NonSecure HW mapped registers
 * MEM_AREA_MAXTYPE:  lower invalid 'type' value
 */
enum teecore_memtypes {
	MEM_AREA_NOTYPE = 0,
	MEM_AREA_TEE_RAM,
	MEM_AREA_TEE_COHERENT,
	MEM_AREA_TA_RAM,
	MEM_AREA_NSEC_SHM,
	MEM_AREA_KEYVAULT,
	MEM_AREA_IO_SEC,
	MEM_AREA_IO_NSEC,
	MEM_AREA_MAXTYPE
};

/* Default NSec shared memory allocated from NSec world */
extern unsigned long default_nsec_shm_paddr;
extern unsigned long default_nsec_shm_size;

void core_init_mmu_map(void);
void core_init_mmu_regs(void);


#ifdef CFG_WITH_LPAE
/*
 * struct core_mmu_user_map - current user mapping register state
 * @ttbr0:	content of ttbr0
 * @enabled:	true if usage of ttbr0 is enabled
 *
 * Note that this struct should be treated as an opaque struct since
 * the content depends on descriptor table format.
 */
struct core_mmu_user_map {
	uint64_t ttbr0;
	bool enabled;
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

/*
 * enum core_mmu_fault - different kinds of faults
 * @CORE_MMU_FAULT_ALIGNMENT:		alignment fault
 * @CORE_MMU_FAULT_DEBUG_EVENT:		debug event
 * @CORE_MMU_FAULT_TRANSLATION:		translation fault
 * @CORE_MMU_FAULT_ASYNC_EXTERNAL:	asynchronous external abort
 * @CORE_MMU_FAULT_OTHER:		Other/unknown fault
 */
enum core_mmu_fault {
	CORE_MMU_FAULT_ALIGNMENT,
	CORE_MMU_FAULT_DEBUG_EVENT,
	CORE_MMU_FAULT_TRANSLATION,
	CORE_MMU_FAULT_PERMISSION,
	CORE_MMU_FAULT_ASYNC_EXTERNAL,
	CORE_MMU_FAULT_OTHER,
};

/*
 * core_mmu_get_fault_type() - get fault type
 * @fsr:	Content of fault status register
 * @returns an enum describing the content of fault status register.
 */
enum core_mmu_fault core_mmu_get_fault_type(uint32_t fsr);

/*
 * core_mmu_create_user_map() - Create user space mapping
 * @mmu:	Generic representation of user space mapping
 * @asid:	Address space identifier for this mapping
 * @map:	MMU configuration to use when activating this VA space
 */
void core_mmu_create_user_map(struct tee_mmu_info *mmu, uint32_t asid,
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
 * core_mmu_set_entry() - Set entry in translation table
 * @tbl_info:	Translation table properties
 * @idx:	Index of entry to update
 * @pa:		Physical address to assign entry
 * @attr:	Attributes to assign entry
 */
void core_mmu_set_entry(struct core_mmu_table_info *tbl_info, unsigned idx,
		paddr_t pa, uint32_t attr);

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

#ifndef CFG_WITH_LPAE
paddr_t core_mmu_get_main_ttb_pa(void);
vaddr_t core_mmu_get_main_ttb_va(void);
paddr_t core_mmu_get_ul1_ttb_pa(void);
vaddr_t core_mmu_get_ul1_ttb_va(void);

/*
 * core_mmu_alloc_l2() - allocates a number of L2 tables
 * @map: description of the area to allocate for
 *
 * Allocates a number of L2 to cover the virtual address range
 * decribed by @map.
 * @returns NULL on failure or a pointer to the L2 table(s)
 */
void *core_mmu_alloc_l2(struct tee_mmap_region *mm);
#endif

void core_mmu_get_mem_by_type(unsigned int type, unsigned int *s,
			      unsigned int *e);

int core_va2pa_helper(void *va, paddr_t *pa);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define core_va2pa(va, pa) (__extension__ ({ \
	paddr_t _p; \
	int _res = core_va2pa_helper((va), &_p); \
	if (!_res) \
		*(pa) = _p; \
	_res; \
	}))
#else
#define core_va2pa(pa, va) \
		core_va2pa_helper((pa), (va))
#endif


int core_pa2va_helper(paddr_t pa, void **va);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define core_pa2va(pa, va) (__extension__ ({ \
	void *_p; \
	int _res = core_pa2va_helper((pa), &_p); \
	if (!_res) \
		*(va) = _p; \
	_res; \
	}))
#else
#define core_pa2va(pa, va) \
	core_pa2va_helper((pa), (va))
#endif



/* routines to retreive shared mem configuration */
bool core_mmu_is_shm_cached(void);

/* L1/L2 cache maintenance (op: refer to ???) */
unsigned int cache_maintenance_l1(int op, void *va, size_t len);
unsigned int cache_maintenance_l2(int op, paddr_t pa, size_t len);
void core_l2cc_mutex_set(void *mutex);
void core_l2cc_mutex_activate(bool en);
void core_l2cc_mutex_lock(void);
void core_l2cc_mutex_unlock(void);

/* various invalidate secure TLB */
enum teecore_tlb_op {
	TLBINV_UNIFIEDTLB,	/* invalidate unified tlb */
	TLBINV_CURRENT_ASID,	/* invalidate unified tlb for current ASID */
	TLBINV_BY_ASID,		/* invalidate unified tlb by ASID */
	TLBINV_BY_MVA,		/* invalidate unified tlb by MVA */
};

struct map_area *bootcfg_get_memory(void);
int core_tlb_maintenance(int op, unsigned int a);
unsigned long bootcfg_get_pbuf_is_handler(void);

/* Cache maintenance operation type */
typedef enum {
	DCACHE_CLEAN = 0x1,
	DCACHE_AREA_CLEAN = 0x2,
	DCACHE_INVALIDATE = 0x3,
	DCACHE_AREA_INVALIDATE = 0x4,
	ICACHE_INVALIDATE = 0x5,
	ICACHE_AREA_INVALIDATE = 0x6,
	WRITE_BUFFER_DRAIN = 0x7,
	DCACHE_CLEAN_INV = 0x8,
	DCACHE_AREA_CLEAN_INV = 0x9,
	L2CACHE_INVALIDATE = 0xA,
	L2CACHE_AREA_INVALIDATE = 0xB,
	L2CACHE_CLEAN = 0xC,
	L2CACHE_AREA_CLEAN = 0xD,
	L2CACHE_CLEAN_INV = 0xE,
	L2CACHE_AREA_CLEAN_INV = 0xF
} t_cache_operation_id;

#endif /* CORE_MMU_H */
