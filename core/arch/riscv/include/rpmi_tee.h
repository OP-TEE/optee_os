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
#include <types_ext.h>
#include <util.h>

/* TEE service group. */
#define RPMI_TEE_SERVICEGROUP_ID	0x0010
#define RPMI_TEE_PROBE_FEATURES		0x02
#define RPMI_TEE_PROBE_SYSTEM		0x03
#define RPMI_TEE_MEMORY_PARCEL_ACCEPT	0x0f
#define RPMI_TEE_MEMORY_PARCEL_RELEASE	0x10
#define RPMI_TEE_MEMORY_SEGMENT_RECEIVE	0x13

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

/* Fixed RPMI memory granule, independent of the host's page size. */
#define RPMI_TEE_PAGE_SHIFT		12
#define RPMI_TEE_PAGE_SIZE		BIT(RPMI_TEE_PAGE_SHIFT)

/* Parcel access permissions. */
#define RPMI_TEE_ACCESS_READ		BIT(29)
#define RPMI_TEE_ACCESS_WRITE		BIT(30)
#define RPMI_TEE_ACCESS_EXEC		BIT(31)

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

/* Memory parcels. */

/*
 * struct rpmi_tee_memory_accept_args - Parcel acceptance arguments
 * @acceptor_id: Local endpoint accepting the parcel
 * @creator_id: Authenticated endpoint that created the parcel
 * @parcel_id: Firmware-assigned parcel identifier
 * @nonce: Creator-supplied parcel nonce
 * @access: Requested acceptor access permissions
 * @creator_access: Expected creator access permissions
 * @pages: Caller-owned array receiving 4 KiB page addresses
 * @page_count_max: Maximum number of entries in pages
 * @page_count: Actual page count, valid only on TEE_SUCCESS
 * @needs_release: Receiver interest was acquired or may have been acquired
 */
struct rpmi_tee_memory_accept_args {
	uint32_t acceptor_id;
	uint32_t creator_id;
	uint32_t parcel_id;
	uint32_t nonce;
	uint32_t access;
	uint32_t creator_access;
	paddr_t *pages;
	size_t page_count_max;
	size_t page_count;
	bool needs_release;
};

/*
 * Accept a parcel with the caller's requested access permissions. The caller
 * supplies page storage and page_count_max in 4 KiB pages. No mapping is
 * exposed before all segments and the total page count have been validated.
 * page_count is valid only on TEE_SUCCESS. Firmware errors become TEE_Result.
 *
 * needs_release records acquired or uncertain receiver interest. On failure,
 * the caller must attempt release. A failed release may leave firmware
 * resources outstanding. Serialize operations on the same parcel and obey the
 * endpoint's concurrent multi-segment-operation limit.
 */
TEE_Result rpmi_tee_memory_accept(struct mbox_chan *channel,
				  struct rpmi_tee_memory_accept_args *args);

/* Release this endpoint's interest, including an incomplete acceptance. */
TEE_Result rpmi_tee_memory_release(struct mbox_chan *channel,
				   uint32_t ep_id, uint32_t parcel_id);

#endif /* __RPMI_TEE_H */
