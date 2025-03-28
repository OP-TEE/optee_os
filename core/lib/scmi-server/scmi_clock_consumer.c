// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <malloc.h>
#include <scmi_agent_configuration.h>
#include <scmi_clock_consumer.h>
#include <tee_api_defines_extensions.h>
#include <dt-bindings/scmi/scmi-clock.h>
#include <trace.h>

/*
 * struct scmi_server_clock: data for a SCMI clock in DT
 *
 * @domain_id: SCMI domain identifier
 * @domain_name: SCMI domain name
 * @clock: clock to control thru SCMI protocol
 * @flags: capabilities of the SCMI clock
 */
struct scmi_server_clock {
	uint32_t domain_id;
	const char *domain_name;
	struct clk *clock;
	uint32_t flags;
};

/*
 * struct scmi_clock_consumer: context of scmi_clock_consumer.c for one channel
 *
 * @plat_clocks: platform clocks exposed with SCMI
 * @plat_clocks_flags: capabilities of an plat_clocks
 * @plat_clocks_count: number of plat_clocks and plat_clocks_flags
 * @link: link for list of scmi_clock_consumer
 */
struct scmi_clock_consumer {
	struct clk *plat_clocks;
	uint32_t *plat_clocks_flags;
	unsigned int plat_clocks_count;

	SLIST_ENTRY(scmi_clock_consumer) link;
};

static SLIST_HEAD(scmi_clock_consumer_head, scmi_clock_consumer) ctx =
	SLIST_HEAD_INITIALIZER(&ctx);

static TEE_Result plat_scmi_clk_get_rates_array(struct clk *clk, size_t index,
						unsigned long *rates,
						size_t *nb_elts)
{
	uint32_t plat_clock_flags = *(uint32_t *)clk->priv;

	if (!nb_elts)
		return TEE_ERROR_BAD_PARAMETERS;

	if (plat_clock_flags & SCMI_CLOCK_ALLOW_SET_RATE)
		return clk_get_rates_array(clk->parent, index, rates, nb_elts);

	if (!rates || !*nb_elts) {
		*nb_elts = 1;
		return TEE_SUCCESS;
	}

	if (index)
		return TEE_ERROR_BAD_PARAMETERS;

	assert(rates);

	/*
	 * Clocks not exposed have no effective parent/platform clock.
	 * Report a 0 Hz rate in this case.
	 */
	if (clk->parent)
		*rates = clk_get_rate(clk->parent);
	else
		*rates = 0;

	*nb_elts = 1;

	return TEE_SUCCESS;
}

static TEE_Result plat_scmi_clk_get_rates_steps(struct clk *clk,
						unsigned long *min,
						unsigned long *max,
						unsigned long *step)
{
	uint32_t plat_clock_flags = *(uint32_t *)clk->priv;

	if (plat_clock_flags & SCMI_CLOCK_ALLOW_SET_RATE) {
		*min = 0;
		*max = UINT32_MAX;
		*step = 0;
	} else {
		*min = clk->rate;
		*max = *min;
		*step = 0;
	}

	return TEE_SUCCESS;
}

static const struct clk_ops plat_scmi_clk_ops = {
	.get_rates_array = plat_scmi_clk_get_rates_array,
	.get_rates_steps = plat_scmi_clk_get_rates_steps,
};

TEE_Result optee_scmi_server_init_clocks(const void *fdt, int node,
					 struct scpfw_agent_config *agent_cfg,
					 struct scpfw_channel_config
						*channel_cfg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct scmi_clock_consumer *consumer = NULL;
	struct scmi_server_clock *s_clocks = NULL;
	size_t s_clocks_count = 0;
	int subnode = 0, item_node = 0;
	bool have_subnodes = false;
	size_t n = 0;
	size_t i = 0;

	item_node = fdt_subnode_offset(fdt, node, "clocks");
	if (item_node < 0)
		return TEE_SUCCESS;

	/* Compute the number of domains to allocate */
	fdt_for_each_subnode(subnode, fdt, item_node) {
		paddr_t reg = fdt_reg_base_address(fdt, subnode);

		assert(reg != DT_INFO_INVALID_REG);
		if ((size_t)reg > s_clocks_count)
			s_clocks_count = (uint32_t)reg;

		have_subnodes = true;
	}

	if (!have_subnodes)
		return TEE_SUCCESS;

	consumer = calloc(1, sizeof(*consumer));
	if (!consumer)
		return TEE_ERROR_OUT_OF_MEMORY;

	SLIST_INSERT_HEAD(&ctx, consumer, link);

	s_clocks_count++;
	s_clocks = calloc(s_clocks_count, sizeof(*s_clocks));
	if (!s_clocks) {
		SLIST_REMOVE_HEAD(&ctx, link);
		free(consumer);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	fdt_for_each_subnode(subnode, fdt, item_node) {
		struct scmi_server_clock *s_clock = NULL;
		const fdt32_t *cuint = NULL;
		struct clk *clock = NULL;
		uint32_t domain_id = 0;

		res = clk_dt_get_by_index(fdt, subnode, 0, &clock);
		if (res == TEE_ERROR_DEFER_DRIVER_INIT) {
			panic("Unexpected init deferral");
		} else if (res) {
			EMSG("Can't get clock %s (%#"PRIx32"), skipped",
			     fdt_get_name(fdt, subnode, NULL), res);
			continue;
		}

		domain_id = (uint32_t)fdt_reg_base_address(fdt, subnode);
		s_clock = s_clocks + domain_id;
		s_clock->domain_id = domain_id;

		cuint = fdt_getprop(fdt, subnode, "domain-name", NULL);
		if (cuint)
			s_clock->domain_name = (char *)cuint;
		else
			s_clock->domain_name = fdt_get_name(fdt, subnode, NULL);

		s_clock->domain_name = strdup(s_clock->domain_name);
		if (!s_clock->domain_name) {
			free(s_clocks);
			SLIST_REMOVE_HEAD(&ctx, link);
			free(consumer);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* Check that the domain_id is not already used */
		if (s_clock->clock) {
			EMSG("Domain ID %"PRIu32" already used", domain_id);
			panic();
		}
		s_clock->clock = clock;

		/*
		 * Get clock flags
		 */
		cuint = fdt_getprop(fdt, subnode, "flags", NULL);
		if (cuint) {
			s_clock->flags = fdt32_to_cpu(*cuint);
			s_clock->flags &= SCMI_CLOCK_MASK;
		}

		DMSG("scmi clock shares %s on domain ID %"PRIu32,
		     s_clock->domain_name, domain_id);
	}

	/*
	 * Assign domain IDs to un-exposed clock as SCMI specification
	 * require the resource is defined even if not accessible.
	 */
	for (n = 0; n < s_clocks_count; n++) {
		if (!s_clocks[n].clock) {
			s_clocks[n].domain_id = n;
			s_clocks[n].domain_name = "";
		}
	}

	if (consumer->plat_clocks || channel_cfg->clock) {
		EMSG("Clock already loaded: agent %u, channel %u",
		     agent_cfg->agent_id, channel_cfg->channel_id);
		panic();
	}

	consumer->plat_clocks_count = s_clocks_count;
	consumer->plat_clocks = calloc(consumer->plat_clocks_count,
				       sizeof(*consumer->plat_clocks));
	assert(consumer->plat_clocks);

	consumer->plat_clocks_flags =
		calloc(consumer->plat_clocks_count,
		       sizeof(*consumer->plat_clocks_flags));
	assert(consumer->plat_clocks_flags);

	channel_cfg->clock_count = s_clocks_count;
	channel_cfg->clock = calloc(channel_cfg->clock_count,
				    sizeof(*channel_cfg->clock));
	assert(channel_cfg->clock);

	for (i = 0; i < s_clocks_count; i++) {
		unsigned int domain_id = s_clocks[i].domain_id;
		struct clk *plat_clock = consumer->plat_clocks + domain_id;
		uint32_t *plat_clock_flags = consumer->plat_clocks_flags +
			domain_id;

		*plat_clock_flags = s_clocks[i].flags;

		plat_clock->ops = &plat_scmi_clk_ops;
		plat_clock->priv = plat_clock_flags;
		plat_clock->name = s_clocks[i].domain_name;
		plat_clock->parent = s_clocks[i].clock;

		if (*plat_clock_flags & SCMI_CLOCK_ALLOW_SET_RATE)
			plat_clock->flags = CLK_SET_RATE_PARENT;

		plat_clock->flags |= CLK_DUTY_CYCLE_PARENT;

		if (clk_register(plat_clock))
			panic();

		channel_cfg->clock[domain_id] = (struct scmi_clock){
			.name = clk_get_name(plat_clock),
			.clk = plat_clock,
			/* Default OFF for RIF issues */
			.enabled = false,
		};
	}

	/* We can free s_clk_channel resources since SCMI server handles them */
	free(s_clocks);

	return TEE_SUCCESS;
}
