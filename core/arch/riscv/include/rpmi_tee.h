/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __RPMI_TEE_H
#define __RPMI_TEE_H

#include <drivers/rpmi_mailbox.h>
#include <rpmi.h>
#include <stdint.h>
#include <tee_api_types.h>

/* TEE service group. */
#define RPMI_TEE_SERVICEGROUP_ID	0x0010
#define RPMI_TEE_PROBE_FEATURES		0x02
#define RPMI_TEE_PROBE_SYSTEM		0x03

/* Feature IDs in TEE_PROBE_FEATURES. */
#define RPMI_TEE_FEATURE_MEMORY_DONATE	0
#define RPMI_TEE_FEATURE_MEMORY_LEND	1
#define RPMI_TEE_FEATURE_MEMORY_SHARE	2
#define RPMI_TEE_FEATURE_SIGNAL_BUS	3
#define RPMI_TEE_FEATURE_MULTISEGMENT_OPS	4

/* Support levels returned for memory features. */
#define RPMI_TEE_MEMORY_UNSUPPORTED	0
#define RPMI_TEE_MEMORY_TEE_ONLY	1
#define RPMI_TEE_MEMORY_FULLY_SUPPORTED	2

/* Discovery. */

/*
 * Query a framework feature on an explicitly selected TEE-group channel.
 * Return local errors or the firmware status converted to TEE_Result.
 * On TEE_SUCCESS, value receives the feature value; otherwise it is zero.
 */
TEE_Result rpmi_tee_probe_features(struct mbox_chan *channel,
				   uint32_t feature_id, uint32_t *value);

/*
 * Discover the calling physical endpoint and domain with TEE_PROBE_SYSTEM.
 * Validate the domain-array extent but do not retain the system topology.
 * Return local errors or the firmware status converted to TEE_Result.
 * On TEE_SUCCESS, domain_id and ep_id receive the caller's identity;
 * otherwise they are zero.
 */
TEE_Result rpmi_tee_probe_system(struct mbox_chan *channel,
				 uint32_t *domain_id, uint32_t *ep_id);

#endif /* __RPMI_TEE_H */
