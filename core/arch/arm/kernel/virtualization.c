/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018 EPAM Systems. All rights reserved. */

#include <compiler.h>
#include <platform_config.h>
#include <kernel/panic.h>
#include <kernel/virtualization.h>
#include <kernel/spinlock.h>
#include <sm/optee_smc.h>

static uint16_t current_client_id = INVALID_CLIENT_ID;
static unsigned int client_id_lock = SPINLOCK_UNLOCK;
static bool client_registered = false;

uint32_t virt_guest_created(uint16_t client_id)
{
	/* This function should be called only with masked exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);

	cpu_spin_lock(&client_id_lock);

	if (client_registered) {
		cpu_spin_unlock(&client_id_lock);
		return OPTEE_SMC_RETURN_ENOTAVAIL;
	}

	current_client_id = client_id;
	client_registered = true;

	cpu_spin_unlock(&client_id_lock);

	return OPTEE_SMC_RETURN_OK;
}

uint32_t virt_guest_destroyed(uint16_t client_id)
{
	/* This function should be called only with masked exceptions */
	assert(thread_get_exceptions() == THREAD_EXCP_ALL);

	cpu_spin_lock(&client_id_lock);

	if (current_client_id == client_id)
		current_client_id = INVALID_CLIENT_ID;

	cpu_spin_unlock(&client_id_lock);
	return OPTEE_SMC_RETURN_OK;
}

bool check_virt_guest(uint16_t client_id)
{
	return client_id == HYP_CLIENT_ID || client_id == current_client_id;
}
