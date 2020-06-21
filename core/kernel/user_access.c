// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2020 Linaro Limited
 */

#include <initcall.h>
#include <kernel/linker.h>
#include <kernel/user_access.h>
#include <mm/tee_mmu.h>
#include <string.h>
#include <tee_api_types.h>
#include <types_ext.h>

static TEE_Result check_user_access(const struct user_mode_ctx *uctx,
				    uint32_t flags, vaddr_t va, size_t len)
{
	return tee_mmu_check_access_rights(uctx, flags, va, len);
}

TEE_Result copy_from_user(void *kaddr, const void *uaddr, size_t len)
{
	struct tee_ta_session *s = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = check_user_access(&to_user_ta_ctx(s->ctx)->uctx,
				TEE_MEMORY_ACCESS_READ |
				TEE_MEMORY_ACCESS_ANY_OWNER,
				(vaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(kaddr, uaddr, len);
	return TEE_SUCCESS;
}

TEE_Result copy_to_user(void *uaddr, const void *kaddr, size_t len)
{
	struct tee_ta_session *s = NULL;
	TEE_Result res = TEE_SUCCESS;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	res = check_user_access(&to_user_ta_ctx(s->ctx)->uctx,
				TEE_MEMORY_ACCESS_WRITE |
				TEE_MEMORY_ACCESS_ANY_OWNER,
				(vaddr_t)uaddr, len);
	if (res != TEE_SUCCESS)
		return res;

	memcpy(uaddr, kaddr, len);
	return TEE_SUCCESS;
}

TEE_Result copy_kaddr_to_uref(uint32_t *uref, void *kaddr)
{
	uint32_t ref = kaddr_to_uref(kaddr);

	return copy_to_user(uref, &ref, sizeof(ref));
}

uint32_t kaddr_to_uref(void *kaddr)
{
	assert(((vaddr_t)kaddr - VCORE_START_VA) < UINT32_MAX);
	return (vaddr_t)kaddr - VCORE_START_VA;
}

vaddr_t uref_to_vaddr(uint32_t uref)
{
	return VCORE_START_VA + uref;
}
