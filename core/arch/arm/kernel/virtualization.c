/* SPDX-License-Identifier: BSD-2-Clause */

#include <compiler.h>
#include <platform_config.h>
#include <kernel/panic.h>
#include <kernel/virtualization.h>
#include <kernel/spinlock.h>
#include <sm/optee_smc.h>

static uint16_t current_client_id = 0;
static unsigned int client_id_lock = SPINLOCK_UNLOCK;

uint32_t virt_guest_created(uint16_t client_id)
{
	/* This function should be called only with masked exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);

	cpu_spin_lock(&client_id_lock);

	if (current_client_id != 0) {
		cpu_spin_unlock(&client_id_lock);
		return OPTEE_SMC_RETURN_ENOTAVAIL;
	}

	current_client_id = client_id;
	cpu_spin_unlock(&client_id_lock);

	return OPTEE_SMC_RETURN_OK;
}

uint32_t virt_guest_destroyed(uint16_t client_id)
{
	/* This function should be called only with masked exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);

	cpu_spin_lock(&client_id_lock);

	if (current_client_id == client_id)
		panic("Hypervisor tries to remove client");

	cpu_spin_unlock(&client_id_lock);
	return OPTEE_SMC_RETURN_OK;
}

bool check_virt_guest(uint16_t client_id)
{
	return client_id == 0 || client_id == current_client_id;
}
