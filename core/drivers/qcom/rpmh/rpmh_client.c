// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <util.h>

#include "rpmh_hal.h"

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AOP_MSG_RAM_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, RPMH_BASE_ADDR,
			CORE_MMU_PGDIR_SIZE);

/* The secure DRV's only AMC TCS, used for active-set dispatch. */
#define RPMH_AMC_TCS	0

/* Commands a single TCS can hold. */
#define RPMH_MAX_TCS_SIZE	16

struct rpmh_driver_data {
	struct client_queue *queue;
	struct mutex lock; /* Protects driver state and client operations */
};

struct client {
	enum rsc_drv_id drv_id;
	const char *name;
	uint32_t req_id;
	SLIST_ENTRY(client) link;
};

struct rpmh_command_set {
	enum rpmh_set set;
	uint32_t num_commands;
	struct rpmh_command commands[RPMH_MAX_TCS_SIZE];
};

SLIST_HEAD(client_list, client);

struct client_queue {
	struct client_list handles;
};

#define AOP_BOOT_COOKIE		0xA0C00C1E
#define MSG_RAM_SECTION_SIZE	0x10000

struct aop_msg_ram_dict {
	uint32_t boot_cookie_offset;
	uint32_t sleep_stats_offset;
	uint32_t reserved_addrs[14];
};

static struct rpmh_driver_data driver_state = {
	.lock = MUTEX_INITIALIZER,
};

static bool tcs_is_idle(uint32_t timeout_us)
{
	uint64_t timer = timeout_init_us(timeout_us);
	bool idle = false;

	while (true) {
		if (hal_rpmh_is_tcs_idle(RPMH_AMC_TCS, &idle) ==
		    HAL_STATUS_SUCCESS && idle)
			return true;

		if (timeout_elapsed(timer))
			return false;

		udelay(1);
	}
}

static uint32_t issue_cmd_set(struct client *client,
			      struct rpmh_command_set *set)
{
	uint32_t enable_mask = 0;
	uint32_t wait_mask = 0;
	uint32_t req_id = 0;
	uint32_t i = 0;

	if (set->set != RPMH_SET_ACTIVE)
		return 0;

	if (!tcs_is_idle(1000)) {
		EMSG("TCS idle timeout for drv %"PRIu32, client->drv_id);
		return 0;
	}

	req_id = ++client->req_id;

	for (i = 0; i < set->num_commands; i++) {
		if (hal_rpmh_write_cmd(RPMH_AMC_TCS, i,
				       set->commands[i].address,
				       set->commands[i].data,
				       set->commands[i].completion) !=
		    HAL_STATUS_SUCCESS) {
			EMSG("Failed to write cmd %"PRIu32" addr 0x%"PRIx32, i,
			     set->commands[i].address);
			return 0;
		}

		enable_mask |= BIT(i);
		if (set->commands[i].completion)
			wait_mask |= BIT(i);
	}

	/* Clear and enable the AMC-finished interrupt before triggering. */
	hal_rpmh_clear_amc_status(RPMH_AMC_TCS);
	hal_rpmh_enable_amc_status(RPMH_AMC_TCS);

	if (hal_rpmh_send_tcs(RPMH_AMC_TCS, enable_mask, wait_mask) !=
	    HAL_STATUS_SUCCESS) {
		EMSG("Failed to send TCS for drv %"PRIu32, client->drv_id);
		return 0;
	}

	return req_id;
}

static struct client *find_client(enum rsc_drv_id drv_id,
				  const char *name)
{
	struct client *client = NULL;

	SLIST_FOREACH(client, &driver_state.queue->handles, link) {
		if (client->drv_id == drv_id && !strcmp(client->name, name))
			return client;
	}

	return NULL;
}

static struct client *create_client(enum rsc_drv_id drv_id,
				    const char *name)
{
	struct client *client = find_client(drv_id, name);

	if (client)
		return client;

	client = calloc(1, sizeof(struct client));
	if (!client)
		return NULL;

	client->drv_id = drv_id;
	client->name = name;
	client->req_id = 0;

	SLIST_INSERT_HEAD(&driver_state.queue->handles, client, link);
	return client;
}

static bool wait_for_cmd(uint32_t req_id)
{
	uint64_t timer = timeout_init_us(10000);
	bool cmd_complete = false;

	if (req_id == 0)
		return true;

	while (!timeout_elapsed(timer)) {
		if (hal_rpmh_get_amc_status(RPMH_AMC_TCS, &cmd_complete))
			cmd_complete = false;

		if (cmd_complete)
			break;

		udelay(1);
	}

	/* Clear the AMC-finished interrupt now that it's been consumed. */
	if (cmd_complete)
		hal_rpmh_clear_amc_status(RPMH_AMC_TCS);

	return cmd_complete;
}

static TEE_Result check_aop_init(void)
{
	uint64_t timer = timeout_init_us(100000);
	struct aop_msg_ram_dict *dict = NULL;
	vaddr_t cookie_addr = 0;
	vaddr_t dict_addr = 0;
	uint32_t cookie = 0;
	vaddr_t base = 0;

	base = (vaddr_t)phys_to_virt(AOP_MSG_RAM_BASE, MEM_AREA_IO_NSEC,
				     AOP_MSG_RAM_SIZE);
	if (!base) {
		EMSG("Failed to get VA for AOP message RAM at PA 0x%lx",
		     (unsigned long)AOP_MSG_RAM_BASE);
		return TEE_ERROR_GENERIC;
	}

	dict_addr = base + AOP_MSG_RAM_SIZE - MSG_RAM_SECTION_SIZE;
	dict = (struct aop_msg_ram_dict *)dict_addr;
	cookie_addr = base + dict->boot_cookie_offset;

	while (cookie != AOP_BOOT_COOKIE) {
		cookie = io_read32(cookie_addr);
		if (cookie == AOP_BOOT_COOKIE)
			break;

		if (timeout_elapsed(timer)) {
			EMSG("AOP boot timeout after 100ms");
			return TEE_ERROR_BUSY;
		}

		udelay(1);
	}

	return TEE_SUCCESS;
}

static TEE_Result rpmh_client_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t base = 0;

	res = check_aop_init();
	if (res != TEE_SUCCESS) {
		EMSG("AOP initialization check failed");
		goto err_panic;
	}

	base = (vaddr_t)phys_to_virt(RPMH_BASE_ADDR, MEM_AREA_IO_SEC,
				     RPMH_RSC_SIZE);
	if (!base) {
		EMSG("Failed to get VA for RSC base at PA 0x%lx",
		     (unsigned long)RPMH_BASE_ADDR);
		goto err_panic;
	}

	if (hal_rpmh_init(base) != HAL_STATUS_SUCCESS) {
		EMSG("Failed to initialize RPMH HAL");
		goto err_panic;
	}

	driver_state.queue = calloc(1, sizeof(struct client_queue));
	if (!driver_state.queue) {
		EMSG("Failed to allocate client queue");
		goto err_panic;
	}

	SLIST_INIT(&driver_state.queue->handles);

	return TEE_SUCCESS;

err_panic:
	panic("RPMH driver initialization failed");
}

struct rpmh_client *rpmh_create_handle(enum rsc_drv_id drv_id,
				       const char *name)
{
	struct rpmh_client *handle = NULL;

	if (!name || drv_id != RSC_DRV_SECURE)
		return NULL;

	mutex_lock(&driver_state.lock);
	handle = (struct rpmh_client *)create_client(drv_id, name);
	mutex_unlock(&driver_state.lock);

	return handle;
}

TEE_Result rpmh_send_command(struct rpmh_client *handle,
			     enum rpmh_set set, bool completion,
			     uint32_t address, uint32_t data,
			     uint32_t *req_id)
{
	struct client *client = (struct client *)handle;
	struct rpmh_command_set cmd_set = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t id = 0;

	if (!client || !req_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*req_id = 0;
	mutex_lock(&driver_state.lock);

	cmd_set.set = set;
	cmd_set.num_commands = 1;
	cmd_set.commands[0].address = address;
	cmd_set.commands[0].data = data;
	cmd_set.commands[0].completion = completion;

	id = issue_cmd_set(client, &cmd_set);
	if (id == 0) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (!wait_for_cmd(id)) {
		res = TEE_ERROR_BUSY;
		goto out;
	}

	*req_id = id;

out:
	mutex_unlock(&driver_state.lock);
	return res;
}

early_init(rpmh_client_init);
