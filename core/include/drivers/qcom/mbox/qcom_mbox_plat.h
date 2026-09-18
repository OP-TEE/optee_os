/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QCOM_MBOX_PLAT_H
#define QCOM_MBOX_PLAT_H

/*
 * Platform-integration interface for the Qualcomm mailbox framework.
 *
 * The platform must implement plat_qcom_mbox_get_data() to return a pointer
 * to a statically-allocated struct qcom_mbox_plat_data describing all
 * available mailbox channels.
 *
 * The returned pointer must remain valid for the lifetime of the driver.
 * The framework does not copy or cache the platform data.
 *
 * Typical platform usage
 * ----------------------
 *
 *   #include <drivers/qcom/mbox/qcom_mbox_plat.h>
 *   #include <drivers/qcom/mbox/qcom_mbox_qmp.h>   // for QMP transport
 *
 *   static const struct qcom_mbox_qmp_config my_qmp_cfg = { ... };
 *   static struct qcom_mbox_qmp_priv         my_qmp_priv;
 *
 *   static const struct qcom_mbox_chan_config plat_channels[] = {
 *       {
 *           .name           = "my-channel",
 *           .ops            = &qcom_mbox_qmp_ops,
 *           .transport_cfg  = &my_qmp_cfg,
 *           .transport_priv = &my_qmp_priv,
 *           .itr_chip       = NULL,  // polling-only; set for IRQ wakeup
 *           .itr_num        = 0,
 *       },
 *   };
 *
 *   static struct qcom_mbox_chan_slot
 *       plat_slots[ARRAY_SIZE(plat_channels)];
 *
 *   static const struct qcom_mbox_plat_data plat_mbox_data = {
 *       .configs      = plat_channels,
 *       .slots        = plat_slots,
 *       .num_channels = ARRAY_SIZE(plat_channels),
 *   };
 *
 *   const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void)
 *   {
 *       return &plat_mbox_data;
 *   }
 *
 * Constraints
 * -----------
 * - configs[N] permanently maps to slots[N].
 * - num_channels must equal ARRAY_SIZE(configs) == ARRAY_SIZE(slots).
 * - All arrays must be statically allocated and remain valid for the
 *   lifetime of the driver.
 * - plat_qcom_mbox_get_data() must return a non-NULL pointer.
 */

#include <stddef.h>

#include <drivers/qcom/mbox/qcom_mbox_types.h>

/*
 * struct qcom_mbox_plat_data — platform-supplied channel table.
 *
 * @configs:      pointer to the immutable channel configuration array.
 * @slots:        pointer to the mutable runtime slot array.
 * @num_channels: number of entries in both arrays.
 */
struct qcom_mbox_plat_data {
	const struct qcom_mbox_chan_config	*configs;
	struct qcom_mbox_chan_slot		*slots;
	size_t					 num_channels;
};

/*
 * plat_qcom_mbox_get_data() — return the platform channel table.
 *
 * Must be implemented by the platform.  Called by the framework core on
 * every qcom_mbox_request() to obtain the channel configuration and runtime
 * slot arrays.
 *
 * The returned pointer must be non-NULL and must remain valid for the
 * lifetime of the driver.  The backing data must be statically allocated.
 */
const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void);

#endif /* QCOM_MBOX_PLAT_H */
