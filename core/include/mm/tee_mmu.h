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
#ifndef TEE_MMU_H
#define TEE_MMU_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager_unpg.h>

/*-----------------------------------------------------------------------------
 * Allocate context resources like ASID and MMU table information
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_init(struct tee_ta_ctx *ctx);

/*-----------------------------------------------------------------------------
 * tee_mmu_final - Release context resources like ASID
 *---------------------------------------------------------------------------*/
void tee_mmu_final(struct tee_ta_ctx *ctx);

/*-----------------------------------------------------------------------------
 * tee_mmu_map - Map parameters, heap, stack and code to user memory map to
 * context
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_map(struct tee_ta_ctx *ctx, struct tee_ta_param *param);


bool tee_mmu_is_vbuf_inside_ta_private(const struct tee_ta_ctx *ctx,
				  const uint32_t va, size_t size);

bool tee_mmu_is_vbuf_outside_ta_private(const struct tee_ta_ctx *ctx,
				  const uint32_t va, size_t size);

/*-----------------------------------------------------------------------------
 * tee_mmu_kernel_to_user - Translate kernel address to user space address
 * given the user context
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_kernel_to_user(const struct tee_ta_ctx *ctx,
				  const uint32_t kaddr, uint32_t *uaddr);

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate virtual user address to physical address
 * given the user context
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_va2pa_helper(const struct tee_ta_ctx *ctx, void *ua,
				     paddr_t *pa);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define tee_mmu_user_va2pa(ctx, va, pa) (__extension__ ({ \
	paddr_t _p; \
	TEE_Result _res = tee_mmu_user_va2pa_helper((ctx), (va), &_p); \
	if (_res == TEE_SUCCESS) \
		*(pa) = _p; \
	_res; \
	}))
#else
#define tee_mmu_user_va2pa(ctx, pa, va) \
		tee_mmu_user_va2pa_helper((ctx), (pa), (va))
#endif

/*-----------------------------------------------------------------------------
 * tee_mmu_user_va2pa - Translate physical address to virtual user address
 * given the user context
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_user_pa2va_helper(const struct tee_ta_ctx *ctx,
				     void *pa, void **va);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define tee_mmu_user_pa2va(ctx, pa, va) (__extension__ ({ \
	void *_p; \
	TEE_Result _res = tee_mmu_user_pa2va_helper((ctx), (pa), &_p); \
	if (_res == TEE_SUCCESS) \
		*(va) = _p; \
	_res; \
	}))
#else
#define tee_mmu_user_pa2va(ctx, pa, va) \
	tee_mmu_user_pa2va_helper((ctx), (pa), (va))
#endif

/*-----------------------------------------------------------------------------
 * tee_mmu_check_access_rights -
 *---------------------------------------------------------------------------*/
TEE_Result tee_mmu_check_access_rights(struct tee_ta_ctx *ctx,
				       uint32_t flags, tee_uaddr_t uaddr,
				       size_t len);

/*-----------------------------------------------------------------------------
 * If ctx is NULL original ROM mapping is restored with ASID 0
 *---------------------------------------------------------------------------*/
void tee_mmu_set_ctx(struct tee_ta_ctx *const ctx);

/* Returns virtual address to which TA is loaded */
uintptr_t tee_mmu_get_load_addr(const struct tee_ta_ctx *const ctx);

/* init some allocation pools */
void tee_mmu_kmap_init(void);
void teecore_init_ta_ram(void);
void teecore_init_pub_ram(void);

/* Maps physical address into kernel space */
TEE_Result tee_mmu_kmap_helper(tee_paddr_t pa, size_t len, void **va);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define tee_mmu_kmap(pa, len, va) (__extension__ ({ \
	void *_p; \
	TEE_Result _res = tee_mmu_kmap_helper((pa), (len), &_p); \
	if (_res == TEE_SUCCESS) \
		*(va) = _p; \
	_res; \
	}))
#else
#define tee_mmu_kmap(va, len, pa) tee_mmu_kmap_helper((va), (len), (pa))
#endif

/*
 * Unmaps a memory mapping previously established with tee_mmu_kmap().
 *
 * Va and len has to be identical to what was supplied/returned from
 * tee_mmu_kmap().
 */
void tee_mmu_kunmap(void *va, size_t len);

TEE_Result tee_mmu_kmap_pa2va_helper(void *pa, void **va);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define tee_mmu_kmap_pa2va(pa, va) (__extension__ ({ \
	void *_p; \
	TEE_Result _res = tee_mmu_kmap_pa2va_helper((pa), &_p); \
	if (_res == TEE_SUCCESS) \
		*(va) = _p; \
	_res; \
	}))
#else
#define tee_mmu_kmap_pa2va(va, pa) tee_mmu_kmap_pa2va_helper((va), (pa))
#endif

TEE_Result tee_mmu_kmap_va2pa_helper(void *va, void **pa);
/* Special macro to avoid breaking strict aliasing rules */
#ifdef __GNUC__
#define tee_mmu_kmap_va2pa(va, pa) (__extension__ ({ \
	void *_p; \
	TEE_Result _res = tee_mmu_kmap_va2pa_helper((va), &_p); \
	if (_res == TEE_SUCCESS) \
		*(pa) = _p; \
	_res; \
	}))
#else
#define tee_mmu_kmap_va2pa(pa, va) tee_mmu_kmap_va2pa_helper((pa), (va))
#endif

bool tee_mmu_kmap_is_mapped(void *va, size_t len);

bool tee_mmu_is_kernel_mapping(void);

uint32_t tee_mmu_kmap_get_cache_attr(void *va);
uint32_t tee_mmu_user_get_cache_attr(struct tee_ta_ctx *ctx, void *va);


#endif
