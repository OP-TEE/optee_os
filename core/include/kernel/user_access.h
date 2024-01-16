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
TEE_Result check_user_access(uint32_t flags, const void *uaddr, size_t len);
TEE_Result copy_from_user_private(void *kaddr, const void *uaddr, size_t len);
TEE_Result copy_from_user(void *kaddr, const void *uaddr, size_t len);
TEE_Result copy_to_user_private(void *uaddr, const void *kaddr, size_t len);
TEE_Result copy_to_user(void *uaddr, const void *kaddr, size_t len);
#else
static inline TEE_Result check_user_access(uint32_t flags __unused,
					   const void *uaddr __unused,
					   size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

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

static inline TEE_Result copy_to_user_private(void *uaddr __unused,
					      const void *kaddr __unused,
					      size_t len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result copy_to_user(void *uaddr __unused,
				      const void *kaddr __unused,
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
 * bb_free_wipe() - Wipe and free a bounce buffer
 * @bb:		Buffer
 * @len:	Length of buffer
 *
 * The bounce buffer is always wiped if @bb is non-NULL, but only freed if
 * it is last on the stack of allocated bounce buffers.
 */
void bb_free_wipe(void *bb, size_t len);

/*
 * bb_reset() - Reset bounce buffer allocation
 *
 * Resets the bounce buffer allocatation state, old pointers allocated
 * with bb_alloc() should not be used any longer.
 */
void bb_reset(void);

TEE_Result clear_user(void *uaddr, size_t n);

size_t strnlen_user(const void *s, size_t n);

#define __BB_MEMDUP(memdup_func, src, len, p) ({			\
	TEE_Result __res = TEE_SUCCESS;					\
	void *__p = NULL;						\
									\
	__res = memdup_func((src), (len), &__p);			\
	if (!__res)							\
		*(p) = __p;						\
	__res;								\
})

/*
 * bb_memdup_user() - Duplicate a user-space buffer into a bounce buffer
 * @src:    Pointer to the user buffer to be duplicated.
 * @len:    Length of the user buffer to be duplicated.
 * @p:      Holds duplicated bounce buffer on success, or unchanged on failure.
 *          Note that the returned buffer is allocated by bb_alloc() and
 *          normally doesn't have to be freed.
 * Return TEE_SUCCESS on success.
 * Return TEE_ERROR_OUT_OF_MEMORY or TEE_ERROR_ACCESS_DENIED on error.
 */
TEE_Result bb_memdup_user(const void *src, size_t len, void **p);
#define BB_MEMDUP_USER(src, len, p) \
	__BB_MEMDUP(bb_memdup_user, (src), (len), (p))

/*
 * bb_memdup_user_private() - Duplicate a private user-space buffer
 * @src:    Pointer to the user buffer to be duplicated. The buffer should
 *          be private to current TA (i.e., !TEE_MEMORY_ACCESS_ANY_OWNER).
 * @len:    Length of the user buffer to be duplicated.
 * @p:      Holds duplicated kernel buffer on success, or unchanged on failure.
 *          Note that the returned buffer is allocated by bb_alloc() and
 *          normally doesn't have to be freed.
 * Return TEE_SUCCESS on success.
 * Return TEE_ERROR_OUT_OF_MEMORY or TEE_ERROR_ACCESS_DENIED on error.
 */
TEE_Result bb_memdup_user_private(const void *src, size_t len, void **p);
#define BB_MEMDUP_USER_PRIVATE(src, len, p) \
	__BB_MEMDUP(bb_memdup_user_private, (src), (len), (p))

/*
 * bb_strndup_user() - Duplicate a user-space string into a bounce buffer
 * @src:    Pointer to the user string to be duplicated.
 * @maxlen: Maximum length of the user string
 * @dst:    Holds duplicated string on success, or unchanged on failure.
 * @dstlen: Length of string, excluding the terminating zero, returned in
 *          @dst.
 *
 * Note that the returned buffer is allocated by bb_alloc() and normally
 * doesn't have to be freed. But if it is to be freed the supplied length
 * to bb_free() should be dstlen + 1.
 *
 * Return TEE_SUCCESS on success.
 * Return TEE_ERROR_OUT_OF_MEMORY or TEE_ERROR_ACCESS_DENIED on error.
 */
TEE_Result bb_strndup_user(const char *src, size_t maxlen, char **dst,
			   size_t *dstlen);

TEE_Result copy_kaddr_to_uref(uint32_t *uref, void *kaddr);

uint32_t kaddr_to_uref(void *kaddr);
vaddr_t uref_to_vaddr(uint32_t uref);
static inline void *uref_to_kaddr(uint32_t uref)
{
	return (void *)uref_to_vaddr(uref);
}

#define GET_USER_SCALAR(_x, _p) ({					\
	TEE_Result __res = TEE_SUCCESS;					\
	typeof(_p) __p = (_p);						\
									\
	static_assert(sizeof(_x) == sizeof(*__p));			\
									\
	__res = copy_from_user(&(_x), (const void *)__p, sizeof(*__p));	\
	__res;								\
})

#define PUT_USER_SCALAR(_x, _p) ({					\
	TEE_Result __res = TEE_SUCCESS;					\
	typeof(_p) __p = (_p);						\
									\
	static_assert(sizeof(_x) == sizeof(*__p));			\
									\
	__res = copy_to_user((void *)__p, &(_x), sizeof(*__p));		\
	__res;								\
})

#endif /*__KERNEL_USER_ACCESS_H*/
