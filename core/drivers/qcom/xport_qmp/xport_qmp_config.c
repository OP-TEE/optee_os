// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include "xport_qmp_config.h"
#include "platform_config.h"

static struct xport_qmp_config xport_qmp_config[GLINK_CFG_MAX_REMOTE_HOSTS] = {
	{
		.version = NULL,
		.remote_ss = "tme",
		.ch_name = "tmeRequest",
		.local_shared_mem_size = TME_QMP_MBOX_SIZE,
		.local_shared_mem = TME_QMP_INBOUND_MBOX_ADDR,
		.remote_shared_mem_size = TME_QMP_MBOX_SIZE,
		.remote_shared_mem = TME_QMP_OUTBOUND_MBOX_ADDR,
		.tx_max_pkt_size = TME_QMP_MBOX_SIZE - TME_QMP_DESC_SIZE,
		.rx_max_pkt_size = TME_QMP_MBOX_SIZE - TME_QMP_DESC_SIZE,
		.rx_pkt_static_buf = TME_QMP_OUTBOUND_MBOX_ADDR +
				     TME_QMP_DESC_SIZE,
		.irq_out = {
			.reg_addr = TME_QMP_IRQ_OUT_REG_ADDR,
			.reg_val = TME_QMP_IRQ_OUT_BIT_MASK,
			.intr_clr_addr = 0,
			.intr_clr_mask = 0,
		},
		.irq_in = TME_QMP_IRQ_IN,
	}
};

const struct xport_qmp_config *xport_qmp_get_config(uint32_t ind)
{
	if (ind >= GLINK_CFG_MAX_REMOTE_HOSTS)
		return NULL;

	return &xport_qmp_config[ind];
}
