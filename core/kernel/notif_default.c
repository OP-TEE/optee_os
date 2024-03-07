// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, Linaro Limited
 */

#include <assert.h>
#include <bitstring.h>
#include <kernel/interrupt.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <trace.h>
#include <types_ext.h>

static bitstr_t bit_decl(notif_values, NOTIF_ASYNC_VALUE_MAX + 1);
static bitstr_t bit_decl(notif_alloc_values, NOTIF_ASYNC_VALUE_MAX + 1);
static unsigned int notif_default_lock = SPINLOCK_UNLOCK;

TEE_Result notif_alloc_async_value(uint32_t *val)
{
	static bool alloc_values_inited;
	uint32_t old_itr_status = 0;
	int bit = 0;

	assert(interrupt_can_raise_pi(interrupt_get_main_chip()));

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	if (!alloc_values_inited) {
		bit_set(notif_alloc_values, NOTIF_VALUE_DO_BOTTOM_HALF);
		alloc_values_inited = true;
	}

	bit_ffc(notif_alloc_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	if (bit >= 0) {
		*val = bit;
		bit_set(notif_alloc_values, bit);
	}

	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);

	if (bit < 0)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

void notif_free_async_value(uint32_t val)
{
	uint32_t old_itr_status = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	assert(val < NOTIF_ASYNC_VALUE_MAX);
	assert(bit_test(notif_alloc_values, val));
	bit_clear(notif_alloc_values, val);

	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
}

uint32_t notif_get_value(bool *value_valid, bool *value_pending)
{
	uint32_t old_itr_status = 0;
	uint32_t res = 0;
	int bit = 0;

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	bit_ffs(notif_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	*value_valid = (bit >= 0);
	if (!*value_valid) {
		*value_pending = false;
		goto out;
	}

	res = bit;
	bit_clear(notif_values, res);
	bit_ffs(notif_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	*value_pending = (bit >= 0);
out:
	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);

	return res;
}

void notif_send_async(uint32_t value)
{
	uint32_t old_itr_status = 0;
	struct itr_chip *itr_chip = interrupt_get_main_chip();

	assert(value <= NOTIF_ASYNC_VALUE_MAX);
	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	bit_set(notif_values, value);
	interrupt_raise_pi(itr_chip, CFG_CORE_ASYNC_NOTIF_GIC_INTID);

	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
}
