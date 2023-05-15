/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TEE_MMU_H
#define TEE_MMU_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_ta.h>

/* Allocate context resources like ASID and MMU table information */
TEE_Result vm_info_init(struct user_mode_ctx *uctx, struct ts_ctx *ts_ctx);

/* Release context resources like ASID */
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
TEE_Result vm_map_param(struct user_mode_ctx *uctx, struct tee_ta_param *param,
			void *param_va[TEE_NUM_PARAMS]);
void vm_clean_param(struct user_mode_ctx *uctx);

/*
 * These two functions are deprecated and should only be called from
 * mobj_seccpy_shm_alloc() and mobj_seccpy_shm_free().
 */
TEE_Result vm_add_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj,
			vaddr_t *va);
void vm_rem_rwmem(struct user_mode_ctx *uctx, struct mobj *mobj, vaddr_t va);

/*
 * User mode private memory is defined as user mode image static segment
 * (code, ro/rw static data, heap, stack). The sole other virtual memory
 * mapped to user mode are memref parameters. These later are considered
 * outside user mode private memory as it might be accessed by the user
 * mode context and its client(s).
 */
bool vm_buf_is_inside_um_private(const struct user_mode_ctx *uctx,
				 const void *va, size_t size);

bool vm_buf_intersects_um_private(const struct user_mode_ctx *uctx,
				  const void *va, size_t size);

TEE_Result vm_buf_to_mboj_offs(const struct user_mode_ctx *uctx,
			       const void *va, size_t size,
			       struct mobj **mobj, size_t *offs);

/* Helper function for virt_to_phys(), shouldn't be used directly elsewhere */
TEE_Result vm_va2pa(const struct user_mode_ctx *uctx, void *ua, paddr_t *pa);

/* Helper function for phys_to_virt(), shouldn't be used directly elsewhere */
void *vm_pa2va(const struct user_mode_ctx *uctx, paddr_t pa, size_t pa_size);

/*
 * Return TEE_SUCCESS or TEE_ERROR_ACCESS_DENIED when buffer exists or return
 * another TEE_Result code.
 */
TEE_Result vm_check_access_rights(const struct user_mode_ctx *uctx,
				  uint32_t flags, uaddr_t uaddr, size_t len);

/* Set user context @ctx or core privileged context if @ctx is NULL */
void vm_set_ctx(struct ts_ctx *ctx);

struct mobj *vm_get_mobj(struct user_mode_ctx *uctx, vaddr_t va, size_t *len,
			 uint16_t *prot, size_t *offs);
#endif /*TEE_MMU_H*/
