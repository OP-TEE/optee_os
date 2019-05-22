/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TEE_MMU_H
#define TEE_MMU_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_ta.h>

/*-----------------------------------------------------------------------------
 * Allocate context resources like ASID and MMU table information
 *---------------------------------------------------------------------------*/
TEE_Result vm_info_init(struct user_ta_ctx *utc);

/*-----------------------------------------------------------------------------
 * Release context resources like ASID
 *---------------------------------------------------------------------------*/
void vm_info_final(struct user_ta_ctx *utc);

/*
 * Creates a memory map of a mobj.
 * Desired virtual address can be specified in @va otherwise @va must be
 * initialized to 0 if the next available can be chosen.
 */
TEE_Result vm_map(struct user_ta_ctx *utc, vaddr_t *va, size_t len,
		  uint32_t prot, struct mobj *mobj, size_t offs);

TEE_Result vm_set_prot(struct user_ta_ctx *utc, vaddr_t va, size_t len,
		       uint32_t prot);

/* Map stack of a user TA.  */
TEE_Result tee_mmu_map_stack(struct user_ta_ctx *utc, struct mobj *mobj);

/*
 * Map a code segment of a user TA, this function may be called multiple
 * times if there's several segments.
 */
TEE_Result tee_mmu_map_add_segment(struct user_ta_ctx *utc, struct mobj *mobj,
				   size_t offs, size_t size, uint32_t prot,
				   vaddr_t *va);

/* Map parameters for a user TA */
TEE_Result tee_mmu_map_param(struct user_ta_ctx *utc,
		struct tee_ta_param *param, void *param_va[TEE_NUM_PARAMS]);
void tee_mmu_clean_param(struct user_ta_ctx *utc);

TEE_Result tee_mmu_add_rwmem(struct user_ta_ctx *utc, struct mobj *mobj,
			     vaddr_t *va);
void tee_mmu_rem_rwmem(struct user_ta_ctx *utc, struct mobj *mobj, vaddr_t va);

/*
 * TA private memory is defined as TA image static segment (code, ro/rw static
 * data, heap, stack). The sole other virtual memory mapped to TA are memref
 * parameters. These later are considered outside TA private memory as it
 * might be accessed by the TA and its client(s).
 */
bool tee_mmu_is_vbuf_inside_ta_private(const struct user_ta_ctx *utc,
				       const void *va, size_t size);

bool tee_mmu_is_vbuf_intersect_ta_private(const struct user_ta_ctx *utc,
					  const void *va, size_t size);

TEE_Result tee_mmu_vbuf_to_mobj_offs(const struct user_ta_ctx *utc,
				     const void *va, size_t size,
				     struct mobj **mobj, size_t *offs);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate virtual user address to physical address
 * given the user context.
 * Interface is deprecated, use virt_to_phys() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_va2pa_helper(const struct user_ta_ctx *utc, void *ua,
				     paddr_t *pa);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate physical address to virtual user address
 * given the user context.
 * Interface is deprecated, use phys_to_virt() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_pa2va_helper(const struct user_ta_ctx *utc,
				     paddr_t pa, void **va);

/*-----------------------------------------------------------------------------
 * tee_mmu_check_access_rights -
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_check_access_rights(const struct user_ta_ctx *utc,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len);

/*-----------------------------------------------------------------------------
 * If ctx is NULL user mapping is removed and ASID set to 0
 *---------------------------------------------------------------------------*/
void tee_mmu_set_ctx(struct tee_ta_ctx *ctx);
struct tee_ta_ctx *tee_mmu_get_ctx(void);

/* Returns virtual address to which TA is loaded */
uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx);

/* init some allocation pools */
void teecore_init_ta_ram(void);
#ifdef CFG_CORE_RESERVED_SHM
void teecore_init_pub_ram(void);
#endif

uint32_t tee_mmu_user_get_cache_attr(struct user_ta_ctx *utc, void *va);

TEE_Result tee_mmu_register_shm(paddr_t pa, size_t len, uint32_t attr);

#endif
