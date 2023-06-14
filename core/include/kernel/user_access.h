/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020, Linaro Limited
 */
#ifndef __KERNEL_USER_ACCESS_H
#define __KERNEL_USER_ACCESS_H

#include <assert.h>
#include <kernel/user_access_arch.h>
#include <tee_api_types.h>
#include <types_ext.h>

#ifdef CFG_WITH_USER_TA
TEE_Result copy_from_user_private(void *kaddr, const void *uaddr, size_t len);
TEE_Result copy_from_user(void *kaddr, const void *uaddr, size_t len);
#else
static inline TEE_Result copy_from_user_private(void *kaddr __unused,
						const void *uaddr __unused,
						size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result copy_from_user(void *kaddr __unused,
					const void *uaddr __unused,
					size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif

/*
 * bb_alloc() - Allocate a bounce buffer
 * @len:	Length of bounce buffer
 *
 * The bounce buffer is allocated from a per user TA context region reserved
 * for bounce buffers. Buffers are allocated in a stack like fashion so
 * only the last buffer can be free. Buffers generally don't have to be
 * freed, all bounce buffer allocations are reset on each syscall entry.
 *
 * Return NULL on failure or a valid pointer on success.
 */
void *bb_alloc(size_t len);

/*
 * bb_free() - Free a bounce buffer
 * @bb:		Buffer
 * @len:	Length of buffer
 *
 * The bounce buffer is only freed if it is last on the stack of allocated
 * bounce buffers. This function does normally not need to be called, see
 * description of bb_alloc().
 */
void bb_free(void *bb, size_t len);

/*
 * bb_reset() - Reset bounce buffer allocation
 *
 * Resets the bounce buffer allocatation state, old pointers allocated
 * with bb_alloc() should not be used any longer.
 */
void bb_reset(void);

TEE_Result copy_to_user_private(void *uaddr, const void *kaddr, size_t len);
TEE_Result copy_to_user(void *uaddr, const void *kaddr, size_t len);

TEE_Result copy_kaddr_to_uref(uint32_t *uref, void *kaddr);

uint32_t kaddr_to_uref(void *kaddr);
vaddr_t uref_to_vaddr(uint32_t uref);
static inline void *uref_to_kaddr(uint32_t uref)
{
	return (void *)uref_to_vaddr(uref);
}

#endif /*__KERNEL_USER_ACCESS_H*/
