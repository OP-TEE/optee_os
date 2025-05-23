// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <drivers/scmi.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <scmi_agent_configuration.h>
#include <scmi_clock_consumer.h>
#include <scmi_reset_consumer.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <util.h>

/*
 * struct optee_scmi_server - Data of scmi_server_scpfw
 *
 * @dt_name: SCMI node name
 * @agent_list: list of optee_scmi_server_agent
 */
struct optee_scmi_server {
	const char *dt_name;
	SIMPLEQ_HEAD(, optee_scmi_server_agent) agent_list;
};

/*
 * @struct optee_scmi_server_agent - Data of an SCMI agent
 *
 * @dt_name: SCMI agent node name
 * @agent_id: SCMI agent identifier
 * @channel_id: SCMI channel identifier
 * @protocol_list: list of optee_scmi_server_protocol
 * @link: link for optee_scmi_server:agent_list
 */
struct optee_scmi_server_agent {
	const char *dt_name;
	unsigned int agent_id;
	unsigned int channel_id;
	SIMPLEQ_HEAD(, optee_scmi_server_protocol) protocol_list;
	SIMPLEQ_ENTRY(optee_scmi_server_agent) link;
};

/*
 * struct optee_scmi_server_protocol - Data of an SCMI protocol
 *
 * @dt_name: SCMI protocol node name
 * @dt_node: SCMI protocol node
 * @protocol_id: SCMI protocol identifier
 * @link: list for optee_scmi_server_agent:protocol_list
 */
struct optee_scmi_server_protocol {
	const char *dt_name;
	int dt_node;
	unsigned int protocol_id;
	SIMPLEQ_ENTRY(optee_scmi_server_protocol) link;
};

/* scmi_agent_configuration API */
static struct scpfw_config scpfw_cfg;

static void scmi_scpfw_free_agent(struct scpfw_agent_config *agent_cfg)
{
	unsigned int j = 0;

	for (j = 0; j < agent_cfg->channel_count; j++) {
		struct scpfw_channel_config *channel_cfg =
			agent_cfg->channel_config + j;

		free(channel_cfg->reset);
		free(channel_cfg->clock);
	}
	free(agent_cfg->channel_config);
}

struct scpfw_config *scmi_scpfw_get_configuration(void)
{
	struct scpfw_agent_config *old_agent_config = scpfw_cfg.agent_config;

	assert(scpfw_cfg.agent_count >= 1);
	assert(!old_agent_config[0].channel_count);

	/*
	 * The agents config data passed to SCP-firmware do not consider
	 * agent ID 0 that is reserved for the SCMI server itself in
	 * SCP-firmware and therefore has no configuration data.
	 */
	scpfw_cfg.agent_count--;
	scpfw_cfg.agent_config = calloc(scpfw_cfg.agent_count,
					sizeof(*scpfw_cfg.agent_config));

	memcpy(scpfw_cfg.agent_config, old_agent_config + 1,
	       sizeof(*scpfw_cfg.agent_config) * scpfw_cfg.agent_count);

	free(old_agent_config);

	return &scpfw_cfg;
}

void scmi_scpfw_release_configuration(void)
{
	unsigned int i = 0;

	for (i = 0; i < scpfw_cfg.agent_count; i++)
		scmi_scpfw_free_agent(scpfw_cfg.agent_config + i);

	free(scpfw_cfg.agent_config);
}

static TEE_Result optee_scmi_server_probe_agent(const void *fdt, int agent_node,
						struct optee_scmi_server_agent
							*agent_ctx)
{
	struct optee_scmi_server_protocol *protocol_ctx = NULL;
	int protocol_node = 0;
	const fdt32_t *cuint = NULL;

	SIMPLEQ_INIT(&agent_ctx->protocol_list);

	/*
	 * Get agent ID from reg property, implicitly a single
	 * 32bit cell value. (required)
	 */
	cuint = fdt_getprop(fdt, agent_node, "reg", NULL);
	if (!cuint) {
		EMSG("%s Missing property reg", agent_ctx->dt_name);
		panic();
	}
	agent_ctx->agent_id = fdt32_to_cpu(*cuint);

	/* Agent ID 0 is strictly reserved to SCMI server. */
	assert(agent_ctx->agent_id > 0);

	if (!fdt_node_check_compatible(fdt, agent_node, "linaro,scmi-optee")) {
		cuint = fdt_getprop(fdt, agent_node, "scmi-channel-id", NULL);
		if (!cuint) {
			EMSG("%s scmi-channel-id property not found",
			     agent_ctx->dt_name);
			panic();
		}
		agent_ctx->channel_id = fdt32_to_cpu(*cuint);
	} else {
		EMSG("%s Incorrect compatible", agent_ctx->dt_name);
		panic();
	}

	fdt_for_each_subnode(protocol_node, fdt, agent_node) {
		const char *node_name = fdt_get_name(fdt, protocol_node, NULL);
		struct optee_scmi_server_protocol *p = NULL;

		if (!strstr(node_name, "protocol@"))
			continue;

		protocol_ctx = calloc(1, sizeof(*protocol_ctx));
		if (!protocol_ctx)
			return TEE_ERROR_OUT_OF_MEMORY;

		protocol_ctx->dt_name = node_name;
		protocol_ctx->dt_node = protocol_node;

		/*
		 * Get protocol ID from reg property, implicitly a single
		 * 32bit cell value. (required)
		 */
		cuint = fdt_getprop(fdt, protocol_node, "reg", NULL);
		if (!cuint) {
			EMSG("%s Missing property reg", protocol_ctx->dt_name);
			panic();
		}
		protocol_ctx->protocol_id = fdt32_to_cpu(*cuint);

		SIMPLEQ_FOREACH(p, &agent_ctx->protocol_list, link)
			assert(p->protocol_id != protocol_ctx->protocol_id);

		SIMPLEQ_INSERT_TAIL(&agent_ctx->protocol_list, protocol_ctx,
				    link);
	}

	return TEE_SUCCESS;
}

static void
optee_scmi_server_init_protocol(const void *fdt,
				struct optee_scmi_server_protocol *protocol_ctx,
				struct scpfw_agent_config *agent_cfg,
				struct scpfw_channel_config *channel_cfg)
{
	switch (protocol_ctx->protocol_id) {
	case SCMI_PROTOCOL_ID_CLOCK:
		if (optee_scmi_server_init_clocks(fdt, protocol_ctx->dt_node,
						  agent_cfg, channel_cfg))
			panic("Error during clocks init");
		break;
	case SCMI_PROTOCOL_ID_RESET_DOMAIN:
		if (optee_scmi_server_init_resets(fdt, protocol_ctx->dt_node,
						  agent_cfg, channel_cfg))
			panic("Error during resets init");
		break;
	default:
		EMSG("%s Unknown protocol ID: %#x", protocol_ctx->dt_name,
		     protocol_ctx->protocol_id);
		panic();
	}
}

static TEE_Result optee_scmi_server_probe(const void *fdt, int parent_node,
					  const void *compat_data __unused)
{
	struct optee_scmi_server *ctx = NULL;
	struct optee_scmi_server_agent *agent_ctx = NULL;
	struct optee_scmi_server_agent *a = NULL;
	TEE_Result res = TEE_SUCCESS;
	unsigned int agent_cfg_count = 0;
	unsigned int i = 0;
	int agent_node = 0;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->dt_name = fdt_get_name(fdt, parent_node, NULL);

	/* Read device tree */
	SIMPLEQ_INIT(&ctx->agent_list);

	fdt_for_each_subnode(agent_node, fdt, parent_node) {
		const char *node_name = fdt_get_name(fdt, agent_node, NULL);

		if (!strstr(node_name, "agent@"))
			continue;

		agent_ctx = calloc(1, sizeof(*agent_ctx));
		if (!agent_ctx) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto fail_agent;
		}
		agent_ctx->dt_name = node_name;

		res = optee_scmi_server_probe_agent(fdt, agent_node, agent_ctx);
		if (res)
			goto fail_agent;

		SIMPLEQ_FOREACH(a, &ctx->agent_list, link)
			assert(a->agent_id != agent_ctx->agent_id);

		SIMPLEQ_INSERT_TAIL(&ctx->agent_list, agent_ctx, link);
		agent_cfg_count = MAX(agent_cfg_count, agent_ctx->agent_id);
	}

	agent_cfg_count++;

	/* Create SCMI config structures */
	scpfw_cfg.agent_count = agent_cfg_count;
	scpfw_cfg.agent_config = calloc(scpfw_cfg.agent_count,
					sizeof(*scpfw_cfg.agent_config));
	if (!scpfw_cfg.agent_config) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		scpfw_cfg.agent_count = 0;
		goto fail_agent;
	}

	SIMPLEQ_FOREACH(agent_ctx, &ctx->agent_list, link) {
		struct scpfw_agent_config *agent_cfg =
			scpfw_cfg.agent_config + agent_ctx->agent_id;

		agent_cfg->name = (const char *)strdup(agent_ctx->dt_name);
		if (!agent_cfg->name) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto fail_scpfw_cfg;
		}

		agent_cfg->agent_id = agent_ctx->agent_id;

		/*
		 * Right now this driver can handle one channel per agent only.
		 */
		assert(agent_ctx->channel_id == 0);
		agent_cfg->channel_count = 1;
		agent_cfg->channel_config =
			calloc(agent_cfg->channel_count,
			       sizeof(*agent_cfg->channel_config));
		if (!agent_cfg->channel_config) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			agent_cfg->channel_count = 0;
			goto fail_scpfw_cfg;
		}

		for (i = 0; i < agent_cfg->channel_count; i++) {
			struct scpfw_channel_config *channel_cfg =
				agent_cfg->channel_config + i;

			channel_cfg->name = "channel";
			channel_cfg->channel_id = agent_ctx->channel_id;
		}
	}

	/* Parse protocols and fill channels config */
	SIMPLEQ_FOREACH(agent_ctx, &ctx->agent_list, link) {
		struct optee_scmi_server_protocol *protocol_ctx = NULL;
		struct scpfw_agent_config *agent_cfg =
			scpfw_cfg.agent_config + agent_ctx->agent_id;
		struct scpfw_channel_config *channel_cfg =
			agent_cfg->channel_config + agent_ctx->channel_id;

		SIMPLEQ_FOREACH(protocol_ctx, &agent_ctx->protocol_list, link)
			optee_scmi_server_init_protocol(fdt, protocol_ctx,
							agent_cfg, channel_cfg);
	}

	return TEE_SUCCESS;

fail_scpfw_cfg:
	scmi_scpfw_release_configuration();

	for (i = 0; i < scpfw_cfg.agent_count; i++)
		free((void *)scpfw_cfg.agent_config[i].name);

fail_agent:
	while (!SIMPLEQ_EMPTY(&ctx->agent_list)) {
		agent_ctx = SIMPLEQ_FIRST(&ctx->agent_list);

		while (!SIMPLEQ_EMPTY(&agent_ctx->protocol_list)) {
			struct optee_scmi_server_protocol *protocol_ctx =
				SIMPLEQ_FIRST(&agent_ctx->protocol_list);

			SIMPLEQ_REMOVE_HEAD(&agent_ctx->protocol_list, link);
			free(protocol_ctx);
		}

		SIMPLEQ_REMOVE_HEAD(&ctx->agent_list, link);
		free(agent_ctx);
	}

	free(ctx);

	return res;
}

static TEE_Result optee_scmi_server_init(void)
{
	const void *fdt = get_embedded_dt();
	int node = -1;

	if (!fdt)
		panic();

	node = fdt_node_offset_by_compatible(fdt, node, "optee,scmi-server");
	if (node < 0)
		panic();

	return optee_scmi_server_probe(fdt, node, NULL);
}

driver_init_late(optee_scmi_server_init);
