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
TEE_Result vm_info_init(struct user_mode_ctx *uctx);

/*-----------------------------------------------------------------------------
 * Release context resources like ASID
 *---------------------------------------------------------------------------*/
void vm_info_final(struct user_mode_ctx *uctx);

/*
 * Creates a memory map of a mobj.
 * Desired virtual address can be specified in @va otherwise @va must be
 * initialized to 0 if the next available can be chosen.
 *
 * @pad_begin and @pad_end specify how much extra free space should be kept
 * when establishing the map. This allows mapping the first part of for
 * instance an ELF file while knowing that the next part which has to be of
 * a certain offset from the first part also will succeed.
 */

TEE_Result vm_map_pad(struct user_mode_ctx *uctx, vaddr_t *va, size_t len,
		      uint32_t prot, uint32_t flags, struct mobj *mobj,
		      size_t offs, size_t pad_begin, size_t pad_end,
		      size_t align);

/*
 * Creates a memory map of a mobj.
 * Desired virtual address can be specified in @va otherwise @va must be
 * initialized to 0 if the next available can be chosen.
 */
static inline TEE_Result vm_map(struct user_mode_ctx *uctx, vaddr_t *va,
				size_t len, uint32_t prot, uint32_t flags,
				struct mobj *mobj, size_t offs)
{
	return vm_map_pad(uctx, va, len, prot, flags, mobj, offs, 0, 0, 0);
}

TEE_Result vm_remap(struct user_mode_ctx *uctx, vaddr_t *new_va, vaddr_t old_va,
		    size_t len, size_t pad_begin, size_t pad_end);

TEE_Result vm_get_flags(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
			uint32_t *flags);

TEE_Result vm_get_prot(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
		       uint16_t *prot);

TEE_Result vm_set_prot(struct user_mode_ctx *uctx, vaddr_t va, size_t len,
		       uint32_t prot);

TEE_Result vm_unmap(struct user_mode_ctx *uctx, vaddr_t va, size_t len);

/* Map parameters for a user TA */
TEE_Result tee_mmu_map_param(struct user_mode_ctx *uctx,
			     struct tee_ta_param *param,
			     void *param_va[TEE_NUM_PARAMS]);
void tee_mmu_clean_param(struct user_mode_ctx *uctx);

TEE_Result tee_mmu_add_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj,
			     vaddr_t *va);
void tee_mmu_rem_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj,
		       vaddr_t va);

/*
 * TA private memory is defined as TA image static segment (code, ro/rw static
 * data, heap, stack). The sole other virtual memory mapped to TA are memref
 * parameters. These later are considered outside TA private memory as it
 * might be accessed by the TA and its client(s).
 */
bool tee_mmu_is_vbuf_inside_um_private(const struct user_mode_ctx *uctx,
				       const void *va, size_t size);

bool tee_mmu_is_vbuf_intersect_um_private(const struct user_mode_ctx *uctx,
					  const void *va, size_t size);

TEE_Result tee_mmu_vbuf_to_mobj_offs(const struct user_mode_ctx *uctx,
				     const void *va, size_t size,
				     struct mobj **mobj, size_t *offs);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate virtual user address to physical address
 * given the user context.
 * Interface is deprecated, use virt_to_phys() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_va2pa_helper(const struct user_mode_ctx *uctx, void *ua,
				     paddr_t *pa);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate physical address to virtual user address
 * given the user context.
 * Interface is deprecated, use phys_to_virt() instead.
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_pa2va_helper(const struct user_mode_ctx *uctx,
				     paddr_t pa, void **va);

/*-----------------------------------------------------------------------------
 * tee_mmu_check_access_rights -
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_check_access_rights(const struct user_mode_ctx *uctx,
				       uint32_t flags, uaddr_t uaddr,
				       size_t len);

/*-----------------------------------------------------------------------------
 * If ctx is NULL user mapping is removed and ASID set to 0
 *---------------------------------------------------------------------------*/
void tee_mmu_set_ctx(struct ts_ctx *ctx);
struct ts_ctx *tee_mmu_get_ctx(void);

/* init some allocation pools */
void teecore_init_ta_ram(void);

uint32_t tee_mmu_user_get_cache_attr(struct user_mode_ctx *uctx, void *va);
#endif /*TEE_MMU_H*/
