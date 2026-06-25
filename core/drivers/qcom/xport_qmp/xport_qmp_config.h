/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __XPORT_QMP_CONFIG_H
#define __XPORT_QMP_CONFIG_H

#include <stdint.h>
#include <types_ext.h>
#include "glink_com.h"

#define TME_QMP_MBOX_SIZE		32u
/* QMP descriptor word that precedes the mailbox payload */
#define TME_QMP_DESC_SIZE		4u

struct xport_qmp_ipc_intr {
	vaddr_t reg_addr;
	uint32_t reg_val;
	uint32_t intr_clr_addr;
	uint32_t intr_clr_mask;
};

struct xport_qmp_config {
	const char *version;
	const char *remote_ss;
	const char *ch_name;
	uint32_t local_shared_mem_size;
	uint32_t local_shared_mem;
	uint32_t remote_shared_mem_size;
	uint32_t remote_shared_mem;
	uint32_t tx_max_pkt_size;
	uint32_t rx_max_pkt_size;
	vaddr_t rx_pkt_static_buf;
	struct xport_qmp_ipc_intr irq_out;
	uint32_t irq_in;
};

const struct xport_qmp_config *xport_qmp_get_config(uint32_t ind);

#endif /* __XPORT_QMP_CONFIG_H */
