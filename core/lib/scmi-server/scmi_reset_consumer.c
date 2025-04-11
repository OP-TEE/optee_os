// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/rstctrl.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <malloc.h>
#include <scmi_agent_configuration.h>
#include <scmi_reset_consumer.h>
#include <tee_api_defines_extensions.h>
#include <trace.h>

/*
 * struct scmi_server_reset: data for a SCMI reset in DT
 *
 * @domain_id: SCMI domain identifier
 * @domain_name: SCMI domain name
 * @reset: reset to control through SCMI protocol
 */
struct scmi_server_reset {
	uint32_t domain_id;
	const char *domain_name;
	struct rstctrl *reset;
};

TEE_Result optee_scmi_server_init_resets(const void *fdt, int node,
					 struct scpfw_agent_config *agent_cfg,
					 struct scpfw_channel_config
							*channel_cfg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct scmi_server_reset *s_resets = NULL;
	size_t s_resets_count = 0;
	int item_node = 0;
	int subnode = 0;
	bool have_subnodes = false;
	size_t n = 0;

	item_node = fdt_subnode_offset(fdt, node, "resets");
	if (item_node < 0)
		return TEE_SUCCESS;

	/* Compute the number of domains to allocate */
	fdt_for_each_subnode(subnode, fdt, item_node) {
		paddr_t reg = fdt_reg_base_address(fdt, subnode);

		assert(reg != DT_INFO_INVALID_REG);
		if (reg > s_resets_count)
			s_resets_count = reg;

		have_subnodes = true;
	}

	if (!have_subnodes)
		return TEE_SUCCESS;

	/* Number of SCMI reset domains is the max domain ID + 1 */
	s_resets_count += 1;
	s_resets = calloc(s_resets_count, sizeof(*s_resets));
	if (!s_resets)
		return TEE_ERROR_OUT_OF_MEMORY;

	fdt_for_each_subnode(subnode, fdt, item_node) {
		struct scmi_server_reset *s_reset = NULL;
		struct rstctrl *reset = NULL;
		const fdt32_t *cuint = NULL;
		uint32_t domain_id = 0;

		res = rstctrl_dt_get_by_index(fdt, subnode, 0, &reset);
		if (res == TEE_ERROR_DEFER_DRIVER_INIT) {
			panic("Unexpected init deferral");
		} else if (res) {
			EMSG("Can't get reset %s (%#"PRIx32"), skipped",
			     fdt_get_name(fdt, subnode, NULL), res);
			continue;
		}

		domain_id = fdt_reg_base_address(fdt, subnode);
		s_reset = s_resets + domain_id;
		s_reset->domain_id = domain_id;

		cuint = fdt_getprop(fdt, subnode, "domain-name", NULL);
		if (cuint)
			s_reset->domain_name = (char *)cuint;
		else
			s_reset->domain_name = fdt_get_name(fdt, subnode, NULL);

		/* Check that the domain_id is not already used */
		if (s_reset->reset) {
			EMSG("Domain ID %"PRIu32" already used", domain_id);
			panic();
		}
		s_reset->reset = reset;

		DMSG("scmi reset shares %s on domain ID %"PRIu32,
		     s_reset->domain_name, domain_id);
	}

	for (n = 0; n < s_resets_count; n++) {
		/*
		 * Assign domain IDs to un-exposed reset as SCMI specification
		 * requires the resource is defined even if not accessible.
		 */
		if (!s_resets[n].reset) {
			s_resets[n].domain_id = n;
			s_resets[n].domain_name = "";
		}

		s_resets[n].domain_name = strdup(s_resets[n].domain_name);
		if (!s_resets[n].domain_name)
			panic();
	}

	if (channel_cfg->reset) {
		EMSG("Reset already loaded: agent %u, channel %u",
		     agent_cfg->agent_id, channel_cfg->channel_id);
		panic();
	}

	channel_cfg->reset_count = s_resets_count;
	channel_cfg->reset = calloc(channel_cfg->reset_count,
				    sizeof(*channel_cfg->reset));
	if (!channel_cfg->reset)
		panic();

	for (n = 0; n < s_resets_count; n++) {
		unsigned int domain_id = s_resets[n].domain_id;

		channel_cfg->reset[domain_id] = (struct scmi_reset){
			.name = s_resets[n].domain_name,
			.rstctrl = s_resets[n].reset,
		};
	}

	return TEE_SUCCESS;
}
