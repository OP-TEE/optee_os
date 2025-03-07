// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2024, Linaro Limited
 */

#include <assert.h>
#include <bitstring.h>
#include <config.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <kernel/notif.h>
#include <kernel/spinlock.h>
#include <kernel/virtualization.h>
#include <trace.h>
#include <types_ext.h>

struct notif_vm_bitmap {
	bool alloc_values_inited;
	bitstr_t bit_decl(values, NOTIF_ASYNC_VALUE_MAX + 1);
	bitstr_t bit_decl(alloc_values, NOTIF_ASYNC_VALUE_MAX + 1);
};

static unsigned int notif_default_lock = SPINLOCK_UNLOCK;
/* Id used to look up the guest specific struct notif_vm_bitmap */
static unsigned int notif_vm_bitmap_id __nex_bss;
/* Notification state when ns-virtualization isn't enabled */
static struct notif_vm_bitmap default_notif_vm_bitmap;

static struct notif_vm_bitmap *get_notif_vm_bitmap(struct guest_partition *prtn)
{
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		if (!prtn)
			return NULL;
		return virt_get_guest_spec_data(prtn, notif_vm_bitmap_id);
	}
	return &default_notif_vm_bitmap;
}

TEE_Result notif_alloc_async_value(uint32_t *val)
{
	struct guest_partition *prtn = NULL;
	struct notif_vm_bitmap *nvb = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t old_itr_status = 0;
	int bit = 0;

	assert(interrupt_can_raise_pi(interrupt_get_main_chip()));

	prtn = virt_get_current_guest();
	nvb = get_notif_vm_bitmap(prtn);
	if (!nvb) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	if (!nvb->alloc_values_inited) {
		bit_set(nvb->alloc_values, NOTIF_VALUE_DO_BOTTOM_HALF);
		nvb->alloc_values_inited = true;
	}

	bit_ffc(nvb->alloc_values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	if (bit < 0) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_unlock;
	}
	*val = bit;
	bit_set(nvb->alloc_values, bit);

out_unlock:
	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
out:
	virt_put_guest(prtn);

	return res;
}

void notif_free_async_value(uint32_t val)
{
	struct guest_partition *prtn = NULL;
	struct notif_vm_bitmap *nvb = NULL;
	uint32_t old_itr_status = 0;

	prtn = virt_get_current_guest();
	nvb = get_notif_vm_bitmap(prtn);
	if (!nvb)
		goto out;

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	assert(val < NOTIF_ASYNC_VALUE_MAX);
	assert(bit_test(nvb->alloc_values, val));
	bit_clear(nvb->alloc_values, val);

	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
out:
	virt_put_guest(prtn);
}

uint32_t notif_get_value(bool *value_valid, bool *value_pending)
{
	struct guest_partition *prtn = NULL;
	struct notif_vm_bitmap *nvb = NULL;
	uint32_t old_itr_status = 0;
	uint32_t res = 0;
	int bit = -1;

	prtn = virt_get_current_guest();
	nvb = get_notif_vm_bitmap(prtn);
	if (!nvb) {
		*value_valid = false;
		goto out;
	}

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	bit_ffs(nvb->values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);
	*value_valid = (bit >= 0);
	if (!*value_valid)
		goto out_unlock;

	res = bit;
	bit_clear(nvb->values, res);
	bit_ffs(nvb->values, (int)NOTIF_ASYNC_VALUE_MAX + 1, &bit);

out_unlock:
	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
out:
	virt_put_guest(prtn);
	*value_pending = (bit >= 0);

	return res;
}

void notif_send_async(uint32_t value, uint16_t guest_id)
{
	struct guest_partition *prtn = NULL;
	struct notif_vm_bitmap *nvb = NULL;
	uint32_t old_itr_status = 0;
	struct itr_chip *itr_chip = interrupt_get_main_chip();

	assert(value <= NOTIF_ASYNC_VALUE_MAX);

	prtn = virt_get_guest(guest_id);
	nvb = get_notif_vm_bitmap(prtn);
	if (!nvb)
		goto out;

	old_itr_status = cpu_spin_lock_xsave(&notif_default_lock);

	bit_set(nvb->values, value);
	interrupt_raise_pi(itr_chip, CFG_CORE_ASYNC_NOTIF_GIC_INTID);

	cpu_spin_unlock_xrestore(&notif_default_lock, old_itr_status);
out:
	virt_put_guest(prtn);
}

static TEE_Result notif_init(void)
{
	if (IS_ENABLED(CFG_NS_VIRTUALIZATION) &&
	    virt_add_guest_spec_data(&notif_vm_bitmap_id,
				     sizeof(struct notif_vm_bitmap), NULL))
		panic("virt_add_guest_spec_data");
	return TEE_SUCCESS;
}
nex_service_init(notif_init);
