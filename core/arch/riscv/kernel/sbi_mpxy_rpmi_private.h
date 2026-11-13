/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2025-2026 NXP
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __SBI_MPXY_RPMI_PRIVATE_H
#define __SBI_MPXY_RPMI_PRIVATE_H

#include <sbi_mpxy.h>

struct sbi_mpxy_rpmi_channel_attrs {
	uint32_t servicegroup_id;
	uint32_t servicegroup_version;
	uint32_t implementation_id;
	uint32_t implementation_version;
};

/* Discovered RPMI protocol attributes and MPXY transfer limits. */
struct sbi_mpxy_rpmi_channel {
	uint32_t channel_id;
	uint32_t max_xfer_len;
	struct sbi_mpxy_channel_attrs attrs;
	struct sbi_mpxy_rpmi_channel_attrs rpmi_attrs;
	struct sbi_mpxy_notification_data *notif;
};

struct sbi_mpxy_rpmi_context {
	uint32_t channel_count;
	struct sbi_mpxy_rpmi_channel *channels;
};

extern struct sbi_mpxy_rpmi_context *sbi_mpxy_rpmi_ctx;

/* Discover RPMI channels before publishing the mailbox controller. */
TEE_Result sbi_mpxy_rpmi_probe_channels(void);

#endif /* __SBI_MPXY_RPMI_PRIVATE_H */
