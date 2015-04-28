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
#include <kernel/tee_common.h>
#include <kernel/tee_l2cc_mutex.h>
#include <mm/tee_mm.h>
#include <core_serviceid.h>
#include <tee_api_defines.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <kernel/tz_proc.h>
#include <trace.h>

/*
 * l2cc_mutex_va holds teecore virtual address of TZ L2CC mutex or NULL.
 *
 * l2cc_mutex_pa holds TZ L2CC mutex physical address. It is relevant only
 * if 'l2cc_mutex_va' hold a non-NULL address.
 *
 * l2cc_mutex_mm hold teecore mm structure used to allocate TZ L2CC mutex,
 * if allocated. Otherwise, it is NULL.
 */
#define MUTEX_SZ sizeof(uint32_t)

static uint32_t *l2cc_mutex_va;
static uint32_t l2cc_mutex_pa;
static tee_mm_entry_t *l2cc_mutex_mm;
static unsigned int *l2cc_mutex;
/*
 * Allocate public RAM to get a L2CC mutex to shared with NSec.
 * Return 0 on success.
 */
static int l2cc_mutex_alloc(void)
{
	void *va;

	if ((l2cc_mutex_va != NULL) || (l2cc_mutex_mm != NULL))
		return -1;

	l2cc_mutex_mm = tee_mm_alloc(&tee_mm_pub_ddr, MUTEX_SZ);
	if (l2cc_mutex_mm == NULL)
		return -1;

	l2cc_mutex_pa = tee_mm_get_smem(l2cc_mutex_mm);

	if (core_pa2va(l2cc_mutex_pa, &va))
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
 * tee_l2cc_mutex_configure - Handle L2 mutex configuration requests from NSec
 *
 * Policy:
 * - if NSec did not register a L2 mutex, default allocate it in public RAM.
 * - if NSec disables L2 mutex, disable the current mutex and unregister it.
 */
TEE_Result tee_l2cc_mutex_configure(t_service_id service_id, uint32_t *mutex)
{
	uint32_t addr;
	void *va;
	int ret = TEE_SUCCESS;

	/*
	 * Enable L2CC: NSec allows teecore to run safe outer maintance
	 *		with shared mutex.
	 * Disable L2CC: NSec will run outer maintenance with locking
	 *		shared mutex. teecore cannot run outer maintenance.
	 * Set L2CC: NSec proposes a Shared Memory locaiotn for the outer
	 *		maintenance shared mutex.
	 * Get L2CC: NSec requests the outer maintenance shared mutex
	 *		location. If NSec has successufully registered one,
	 *		return its location, otherwise, allocated one in NSec
	 *		and provided NSec the physical location.
	 */
	switch (service_id) {
	case SERVICEID_ENABLE_L2CC_MUTEX:
		if (l2cc_mutex_va == 0) {
			ret = l2cc_mutex_alloc();
			if (ret)
				return TEE_ERROR_GENERIC;
		}
		l2cc_mutex_set(l2cc_mutex_va);
		break;
	case SERVICEID_DISABLE_L2CC_MUTEX:
		if (l2cc_mutex_mm) {
			tee_mm_free(l2cc_mutex_mm);
			l2cc_mutex_mm = NULL;
		}
		l2cc_mutex_va = NULL;
		l2cc_mutex_set(NULL);
		break;
	case SERVICEID_GET_L2CC_MUTEX:
		if (l2cc_mutex_va == NULL) {
			ret = l2cc_mutex_alloc();
			if (ret)
				return TEE_ERROR_GENERIC;
		}
		*mutex = l2cc_mutex_pa;
		break;
	case SERVICEID_SET_L2CC_MUTEX:
		if (l2cc_mutex_va != NULL)
			return TEE_ERROR_BAD_PARAMETERS;
		addr = *mutex;
		if (core_pbuf_is(CORE_MEM_NSEC_SHM, addr, MUTEX_SZ) == false)
			return TEE_ERROR_BAD_PARAMETERS;
		if (core_pa2va(addr, &va))
			return TEE_ERROR_BAD_PARAMETERS;
		l2cc_mutex_pa = addr;
		l2cc_mutex_va = va;
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return ret;
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
