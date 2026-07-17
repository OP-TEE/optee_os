/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_SUBSYS_H
#define PAS_SUBSYS_H

#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>

#include "pas_data.h"
#include "resource_table.h"

/*
 * struct qcom_pas_ops : per-subsystem firmware operations.
 *
 * Each remoteproc subsystem a platform supports provides one of these.  Any
 * member may be NULL when the subsystem does not implement that operation;
 * the generic core (pas_core.c) returns the appropriate error in that case.
 *
 * @fw_start:           Program the firmware entry and run the boot FSM.
 * @fw_shutdown:        Put the processor back into reset.
 * @fw_set_state:       Power the processor on (@on == true) or off.
 * @get_resource_table: Serialise the firmware resource table (see
 *                      resource_table.h).  NULL for subsystems with no table.
 */
struct qcom_pas_ops {
	TEE_Result (*fw_start)(struct qcom_pas_data *data);
	TEE_Result (*fw_shutdown)(struct qcom_pas_data *data);
	TEE_Result (*fw_set_state)(struct qcom_pas_data *data, bool on);
	TEE_Result (*get_resource_table)(struct resource_table *rt,
					 size_t *size);
};

/*
 * enum qcom_pas_reset_seq : clock/reset sequence auth_and_reset runs around
 * the subsystem's fw_start op.
 *
 * @QCOM_PAS_RESET_NONE:       fw_start only; no clock management here.
 * @QCOM_PAS_RESET_CLK_ENABLE: qcom_clock_enable() then fw_start().
 * @QCOM_PAS_RESET_CLK_FULL:   qcom_clock_pas_reset(), qcom_clock_enable(),
 *                             fw_start(), then
 *                             qcom_clock_enable_pas_processor().
 */
enum qcom_pas_reset_seq {
	QCOM_PAS_RESET_NONE = 0,
	QCOM_PAS_RESET_CLK_ENABLE,
	QCOM_PAS_RESET_CLK_FULL,
};

/*
 * struct qcom_pas_subsys : one remoteproc subsystem on a platform.
 *
 * @data:      Runtime state, seeded with the static pas_id / base / size /
 *             clk_group and updated during mem_setup and bring-up.
 * @ops:       Firmware operations for this subsystem.
 * @reset_seq: Clock/reset sequence auth_and_reset must run.
 *
 * Platform descriptor tables are writable because @data is mutated at
 * runtime.
 */
struct qcom_pas_subsys {
	struct qcom_pas_data data;
	const struct qcom_pas_ops *ops;
	enum qcom_pas_reset_seq reset_seq;
};

/*
 * qcom_pas_platform_subsys() : return this platform's subsystem table.
 *
 * Implemented once per platform flavor in platform/<flavor>/subsys.c.
 *
 * @count: out, number of entries in the returned table.
 * Returns the (writable) descriptor array.
 */
struct qcom_pas_subsys *qcom_pas_platform_subsys(size_t *count);

/*
 * pas_lookup() : find the subsystem entry matching @pas_id in the platform's
 * subsystem table, or NULL if unknown.
 */
struct qcom_pas_subsys *pas_lookup(uint32_t pas_id);

#endif /* PAS_SUBSYS_H */
