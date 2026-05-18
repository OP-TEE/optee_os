// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/qcom/cmd_db/cmd_db.h>
#include <drivers/qcom/rpmh/rpmh_client.h>
#include <initcall.h>
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
#include "rpmh_resource_commands.h"
#include "rpmh_tcs.h"

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, AOP_MSG_RAM_BASE,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, RPMH_BASE_ADDR,
			CORE_MMU_PGDIR_SIZE);

struct rpmh_driver_data {
	vaddr_t rsc_base;
	struct client_queue *queue;
	struct mutex lock; /* Protects driver state and client operations */
};

struct client {
	enum rsc_drv_id drv_id;
	const char *name;
	uint32_t req_id;
	uint32_t oldest_req_id;
	uint32_t num_reqs_in_progress;
	struct explicit_cmd_set *cmds;
	SLIST_ENTRY(client) link;
};

struct explicit_cmd_set {
	uint32_t in_use;
	uint32_t total;
	struct cmd_set_internal *sets;
};

struct cmd_set_internal {
	enum rpmh_set set;
	uint32_t count;
	uint32_t dependency_bmsk;
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

static bool tcs_is_idle(enum rsc_drv_id drv_id, uint32_t timeout_us)
{
	uint64_t timer = timeout_init_us(timeout_us);

	while (!rpmh_tcs_is_amc_free(drv_id)) {
		if (timeout_elapsed(timer))
			return false;
		udelay(1);
	}

	return true;
}

static uint32_t issue_cmd_set_internal(struct client *client,
				       struct cmd_set_internal *set)
{
	struct rpmh_resource_command temp_rc;
	struct rpmh_resource_command *rc;
	uint32_t enable_mask, req_id;
	uint32_t addr, data, i;
	bool dirty = false;
	bool completion;

	for (i = 0; i < set->count; i++) {
		addr = set->commands[i].address;
		data = set->commands[i].data;
		completion = set->commands[i].completion;

		rc = rpmh_find_resource_command(addr);
		if (!rc) {
			rpmh_resource_command_init(&temp_rc, addr);
			rc = &temp_rc;
		}

		if (rpmh_resource_command_update(rc, set->set, data,
						 completion, client->drv_id,
						 false))
			dirty = true;
	}

	if (!dirty || set->set != RPMH_SET_ACTIVE)
		return 0;

	if (!tcs_is_idle(client->drv_id, 1000)) {
		EMSG("TCS idle timeout for drv %u", client->drv_id);
		return 0;
	}

	req_id = ++client->req_id;
	client->num_reqs_in_progress++;

	for (i = 0; i < set->count; i++) {
		if (hal_rpmh_write_cmd(client->drv_id, 0, i,
				       set->commands[i].address,
				       set->commands[i].data,
				       set->commands[i].completion) !=
		    HAL_STATUS_SUCCESS) {
			EMSG("Failed to write cmd %u addr 0x%x", i,
			     set->commands[i].address);
			return 0;
		}
	}

	enable_mask = GENMASK_32(set->count - 1, 0);
	if (hal_rpmh_send_tcs(client->drv_id, 0, enable_mask) !=
	    HAL_STATUS_SUCCESS) {
		EMSG("Failed to send TCS for drv %u", client->drv_id);
		return 0;
	}

	return req_id;
}

static struct client *find_client(enum rsc_drv_id drv_id,
				  const char *name)
{
	struct client *client;

	SLIST_FOREACH(client, &driver_state.queue->handles, link) {
		if (client->drv_id == drv_id && !strcmp(client->name, name))
			return client;
	}

	return NULL;
}

static struct client *create_client(enum rsc_drv_id drv_id,
				    const char *name, bool explicit)
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
	client->oldest_req_id = 0;
	client->num_reqs_in_progress = 0;

	if (explicit) {
		client->cmds = calloc(1, sizeof(struct explicit_cmd_set));
		if (!client->cmds) {
			free(client);
			return NULL;
		}
	}

	SLIST_INSERT_HEAD(&driver_state.queue->handles, client, link);
	return client;
}

static bool wait_for_cmd(struct client *client, uint32_t req_id,
			 bool wait_all)
{
	uint64_t timer = timeout_init_us(10000);
	bool cmd_complete = false;

	if (req_id == 0)
		return true;

	while (!timeout_elapsed(timer)) {
		if (wait_all)
			cmd_complete = (client->num_reqs_in_progress == 0);
		else if (hal_rpmh_get_amc_status(client->drv_id, 0,
						 &cmd_complete))
			cmd_complete = false;

		if (cmd_complete)
			break;

		udelay(1);
	}

	if (cmd_complete && client->num_reqs_in_progress > 0)
		client->num_reqs_in_progress--;

	return cmd_complete;
}

static TEE_Result check_aop_init(void)
{
	uint64_t timer = timeout_init_us(100000);
	vaddr_t cookie_addr, dict_addr, base;
	struct aop_msg_ram_dict *dict;
	uint32_t cookie = 0;

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
	TEE_Result res;

	res = check_aop_init();
	if (res != TEE_SUCCESS) {
		EMSG("AOP initialization check failed");
		goto err_panic;
	}

	driver_state.rsc_base = (vaddr_t)phys_to_virt(RPMH_BASE_ADDR,
						      MEM_AREA_IO_SEC,
						      RPMH_RSC_SIZE);
	if (!driver_state.rsc_base) {
		EMSG("Failed to get VA for RSC base at PA 0x%lx",
		     (unsigned long)RPMH_BASE_ADDR);
		goto err_panic;
	}

	driver_state.queue = calloc(1, sizeof(struct client_queue));
	if (!driver_state.queue) {
		EMSG("Failed to allocate client queue");
		goto err_panic;
	}

	SLIST_INIT(&driver_state.queue->handles);

	if (hal_rpmh_init(driver_state.rsc_base) != HAL_STATUS_SUCCESS ||
	    rpmh_tcs_init() != TEE_SUCCESS) {
		EMSG("Failed to initialize HAL/TCS");
		goto err_panic;
	}

	return TEE_SUCCESS;

err_panic:
	panic("RPMH driver initialization failed");
}

struct rpmh_client *rpmh_create_handle(enum rsc_drv_id drv_id,
				       const char *name)
{
	struct rpmh_client *handle;

	if (!name || drv_id != RSC_DRV_SECURE)
		return NULL;

	mutex_lock(&driver_state.lock);
	handle = (struct rpmh_client *)create_client(drv_id, name, false);
	mutex_unlock(&driver_state.lock);

	return handle;
}

TEE_Result rpmh_send_command(struct rpmh_client *handle,
			     enum rpmh_set set, bool completion,
			     uint32_t address, uint32_t data,
			     uint32_t *req_id)
{
	struct client *client = (struct client *)handle;
	struct cmd_set_internal cmd_set = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t id;

	if (!client || !req_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*req_id = 0;
	mutex_lock(&driver_state.lock);

	cmd_set.commands[0].address = address;
	cmd_set.commands[0].data = data;
	cmd_set.commands[0].completion = completion;
	cmd_set.set = set;
	cmd_set.count = 1;
	cmd_set.dependency_bmsk = 0;

	id = issue_cmd_set_internal(client, &cmd_set);
	if (id == 0) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (!wait_for_cmd(client, id, false)) {
		res = TEE_ERROR_BUSY;
		goto out;
	}

	*req_id = id;

out:
	mutex_unlock(&driver_state.lock);
	return res;
}

void rpmh_barrier_single(struct rpmh_client *handle, uint32_t req_id)
{
	struct client *client = (struct client *)handle;

	if (!client)
		return;

	wait_for_cmd(client, req_id, false);
}

early_init(rpmh_client_init);
