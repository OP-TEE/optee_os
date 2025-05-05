/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023-2025, STMicroelectronics
 */

#ifndef SCMI_AGENT_CONFIGURATION_H
#define SCMI_AGENT_CONFIGURATION_H

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <stdbool.h>
#include <stddef.h>

/* Structure used to describe the SCMI agents */

/*
 * struct scmi_clock - Description of a clock domain
 * @name: Domain name
 * @clk: Clock instance controlled by the domain
 * @enabled: Default state of the clock
 */
struct scmi_clock {
	const char *name;
	struct clk *clk;
	bool enabled;
};

/*
 * struct scmi_reset - Description of a reset domain
 * @name: Domain name
 * @rstctrl: Reset controlled by the domain
 */
struct scmi_reset {
	const char *name;
	struct rstctrl *rstctrl;
};

/*
 * struct scpfw_channel_config - SCMI channel resources
 * @name: Channel name
 * @channel_id: ID for the channel in OP-TEE SCMI bindings
 * @clock: Description of the clocks exposed on the channel
 * @clock_count: Number of cells of @clock
 * @reset: Description of the reset conntrollers exposed on the channel
 * @reset_count: Number of cells of @reset
 */
struct scpfw_channel_config {
	const char *name;
	unsigned int channel_id;
	struct scmi_clock *clock;
	size_t clock_count;
	struct scmi_reset *reset;
	size_t reset_count;
};

/*
 * struct scpfw_agent_config - SCMI agent description
 * @name: Agent name exposed through SCMI
 * @agent_id: Agent ID exposed through SCMI
 * @channel_config: Channels exposed by the agent
 * @channel_count: Number of cells in @channel_config
 *
 * There is currently a constraint that mandates @agent_id is the
 * index minus 1 of the agent in array struct scpfw_config::agent_config
 * This is because there is no config data for agent ID 0 that is
 * reserved as the ID of the SCMI server itself in SCP-firmware.
 */
struct scpfw_agent_config {
	const char *name;
	unsigned int agent_id;
	struct scpfw_channel_config *channel_config;
	size_t channel_count;
};

/*
 * struct scpfw_config - SCP firmware configuration root node
 * @agent_config: Agents exposed with SCMI
 * @agent_count: Number of cells in @agent_config
 */
struct scpfw_config {
	struct scpfw_agent_config *agent_config;
	size_t agent_count;
};

#ifdef CFG_SCMI_SCPFW_FROM_DT
/* Get the platform configuration data for the SCP firmware */
struct scpfw_config *scmi_scpfw_get_configuration(void);

/* Release resources allocated to create SCP-firmware configuration data */
void scmi_scpfw_release_configuration(void);

#else
static inline struct scpfw_config *scmi_scpfw_get_configuration(void)
{
	return NULL;
}

static inline void scmi_scpfw_release_configuration(void)
{
}
#endif /* CFG_SCMI_SCPFW_FROM_DT */

#endif /* SCMI_AGENT_CONFIGURATION_H */
