/* SPDX-License-Identifier: BSD-2-Clause */

#include <compiler.h>
#include <platform_config.h>
#include <kernel/panic.h>
#include <kernel/virtualization.h>
#include <sm/optee_smc.h>

static uint16_t current_client_id = 0;

uint32_t client_created(uint16_t client_id)
{
	if (current_client_id != 0)
		return OPTEE_SMC_RETURN_ENOTAVAIL;

	current_client_id = client_id;

	return OPTEE_SMC_RETURN_OK;
}

uint32_t client_destroyed(uint16_t client_id)
{
	if (current_client_id == client_id)
		panic("Hypervisor tries to remove client");

	return OPTEE_SMC_RETURN_OK;
}

bool check_client(uint16_t client_id)
{
	return client_id == 0 || client_id == current_client_id;
}
