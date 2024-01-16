/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2022, Linaro Limited
 */
#ifndef __SCMI_SCMI_SERVER_H
#define __SCMI_SCMI_SERVER_H

#include <tee_api_types.h>
#include <types_ext.h>

#ifdef CFG_SCMI_SCPFW
/*
 * Request processing of an incoming event in the SCMI server for a target
 * MHU/SMT mailbox.
 *
 * @channel_id: SCMI channel handler
 */
TEE_Result scmi_server_smt_process_thread(unsigned int channel_id);

/*
 * Request processing of an incoming event in the SCMI server for a target
 * MHU/MSG mailbox.
 *
 * @id: SCMI channel handler
 * @in_buf: Input message MSG buffer
 * @in_size: Input message MSG buffer size
 * @out_buf: Output message MSG buffer
 * @out_size: Reference to output message MSG buffer size
 */
TEE_Result scmi_server_msg_process_thread(unsigned int channel_id, void *in_buf,
					  size_t in_size, void *out_buf,
					  size_t *out_size);

/*
 * Get SCP-firmware channel device ID from the client channel ID.
 *
 * @channel_id: SCMI channel handler
 * @handle: Output SCP-firmware device ID for the target SCMI mailbox
 */
TEE_Result scmi_server_get_channel(unsigned int channel_id, int *handle);

/* Get number of channels supported by the SCMI platform/server */
int scmi_server_get_channels_count(void);

#else /* CFG_SCMI_SCPFW */
static inline
TEE_Result scmi_server_smt_process_thread(unsigned int channel_id __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline
TEE_Result scmi_server_msg_process_thread(unsigned int channel_id __unused,
					  void *in_buf __unused,
					  size_t in_size __unused,
					  void *out_buf __unused,
					  size_t *out_size __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result scmi_server_get_channel(unsigned int id __unused,
						 int *handle __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline int scmi_server_get_channels_count(void)
{
	return 0;
}
#endif /* CFG_SCMI_SCPFW */
#endif /* __SCMI_SCMI_SERVER_H */
