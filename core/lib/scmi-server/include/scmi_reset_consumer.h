/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics
 */

#ifndef SCMI_SERVER_RESET_CONSUMER_H
#define SCMI_SERVER_RESET_CONSUMER_H

#include <scmi_agent_configuration.h>
#include <stdint.h>
#include <tee_api_types.h>

#ifdef CFG_SCMI_SERVER_RESET_CONSUMER
/*
 * Initialize SCMI reset from reset consumer information from DT.
 * Returns a TEE_Result compliant value
 */
TEE_Result optee_scmi_server_init_resets(const void *fdt, int node,
					 struct scpfw_agent_config *agent_cfg,
					 struct scpfw_channel_config
							*channel_cfg);
#else
static inline TEE_Result
optee_scmi_server_init_resets(const void *fdt __unused, int node __unused,
			      struct scpfw_agent_config *agent_cfg __unused,
			      struct scpfw_channel_config *channel_cfg __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_SCMI_SERVER_RESET_CONSUMER */
#endif /* SCMI_SERVER_RESET_CONSUMER_H */
