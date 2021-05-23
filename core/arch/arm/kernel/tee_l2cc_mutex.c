// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <kernel/tee_common.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/spinlock.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee_api_defines.h>
#include <trace.h>

/*
 * l2cc_mutex_va holds teecore virtual address of TZ L2CC mutex or NULL.
 *
 * l2cc_mutex_pa holds TZ L2CC mutex physical address. It is relevant only
 * if 'l2cc_mutex_va' hold a non-NULL address.
 */
#define MUTEX_SZ sizeof(uint32_t)

static uint32_t *l2cc_mutex_va;
static uint32_t l2cc_mutex_pa;
static uint32_t l2cc_mutex_boot_pa;
static unsigned int *l2cc_mutex;

void tee_l2cc_store_mutex_boot_pa(uint32_t pa)
{
	l2cc_mutex_boot_pa = pa;
}

/*
 * Allocate public RAM to get a L2CC mutex to shared with NSec.
 * Return 0 on success.
 */
static int l2cc_mutex_alloc(void)
{
	void *va;

	if (l2cc_mutex_va != NULL)
		return -1;

	l2cc_mutex_pa = l2cc_mutex_boot_pa;

	va = phys_to_virt(l2cc_mutex_pa, MEM_AREA_NSEC_SHM, MUTEX_SZ);
	if (!va)
		return -1;

	*(uint32_t *)va = 0;
	l2cc_mutex_va = va;
	return 0;
}

static void l2cc_mutex_set(void *mutex)
{
	l2cc_mutex = (unsigned int *)mutex;
}

/*
 * tee_xxx_l2cc_mutex():  Handle L2 mutex configuration requests from NSec
 *
 * Policy:
 * - if NSec did not register a L2 mutex, default allocate it in public RAM.
 * - if NSec disables L2 mutex, disable the current mutex and unregister it.
 *
 * Enable L2CC: NSec allows teecore to run safe outer maintance
 *		with shared mutex.
 * Disable L2CC: NSec will run outer maintenance with locking
 *               shared mutex. teecore cannot run outer maintenance.
 * Set L2CC: NSec proposes a Shared Memory locaiotn for the outer
 *           maintenance shared mutex.
 * Get L2CC: NSec requests the outer maintenance shared mutex
 *           location. If NSec has successufully registered one,
 *           return its location, otherwise, allocated one in NSec
 *           and provided NSec the physical location.
 */
TEE_Result tee_enable_l2cc_mutex(void)
{
	int ret;

	if (!l2cc_mutex_va) {
		ret = l2cc_mutex_alloc();
		if (ret)
			return TEE_ERROR_GENERIC;
	}
	l2cc_mutex_set(l2cc_mutex_va);
	return TEE_SUCCESS;
}

TEE_Result tee_disable_l2cc_mutex(void)
{
	l2cc_mutex_va = NULL;
	l2cc_mutex_set(NULL);
	return TEE_SUCCESS;
}

TEE_Result tee_get_l2cc_mutex(paddr_t *mutex)
{
	int ret;

	if (!l2cc_mutex_va) {
		ret = l2cc_mutex_alloc();
		if (ret)
			return TEE_ERROR_GENERIC;
	}
	*mutex = l2cc_mutex_pa;
	return TEE_SUCCESS;
}

TEE_Result tee_set_l2cc_mutex(paddr_t *mutex)
{
	uint32_t addr;
	void *va;

	if (l2cc_mutex_va != NULL)
		return TEE_ERROR_BAD_PARAMETERS;
	addr = *mutex;
	va = phys_to_virt(addr, MEM_AREA_NSEC_SHM, MUTEX_SZ);
	if (!va)
		return TEE_ERROR_BAD_PARAMETERS;
	l2cc_mutex_pa = addr;
	l2cc_mutex_va = va;
	return TEE_SUCCESS;
}

void tee_l2cc_mutex_lock(void)
{
	if (l2cc_mutex)
		cpu_spin_lock(l2cc_mutex);
}

void tee_l2cc_mutex_unlock(void)
{
	if (l2cc_mutex)
		cpu_spin_unlock(l2cc_mutex);
}
