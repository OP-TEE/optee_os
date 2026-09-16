// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Channel table of the bobcat SoCs: one QMP-Lite channel to TME-Lite.
 * TME_QMP_LITE_{INBOUND,OUTBOUND}_MBOX_ADDR are named from the TME's point of
 * view: INBOUND is what the TME reads (our TX mailbox), OUTBOUND is what it
 * writes (our RX mailbox). Each starts with the 4-byte QMP-Lite descriptor
 * register, followed by the payload.
 */

#include <initcall.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "qcom_mbox_private.h"
#include "qcom_mbox_qmp_lite.h"

/* The descriptor register followed by the payload */
#define TME_QMP_LITE_MBOX_REGION_SIZE \
	(QMP_LITE_DESC_SIZE + TME_QMP_LITE_MBOX_SIZE)

/* The doorbell is a single 32-bit register */
#define TME_QMP_LITE_IRQ_OUT_REG_SIZE	sizeof(uint32_t)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
			TME_QMP_LITE_MBOX_REGION_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_INBOUND_MBOX_ADDR,
			TME_QMP_LITE_MBOX_REGION_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_IRQ_OUT_REG_ADDR,
			TME_QMP_LITE_IRQ_OUT_REG_SIZE);

static struct qcom_mbox_qmp_lite_config tme_qmp_lite_cfg;
static struct qcom_mbox_qmp_lite_priv tme_qmp_lite_priv;

/*
 * Channels. transport_cfg is filled in by plat_qcom_mbox_init() once the
 * regions are mapped.
 */
static struct qcom_mbox_chan mbox_channels[] = {
	{
		.name = TME_QMP_LITE_CHANNEL_NAME,
		.ops = &qcom_mbox_qmp_lite_ops,
		.transport_priv = &tme_qmp_lite_priv,
		.lock = MUTEX_INITIALIZER,
	},
};

static const struct qcom_mbox_plat_data mbox_plat_data = {
	.channels = mbox_channels,
	.num_channels = ARRAY_SIZE(mbox_channels),
};

static TEE_Result plat_qcom_mbox_init(void)
{
	vaddr_t tx_base = 0;
	vaddr_t rx_base = 0;
	vaddr_t irq_reg = 0;

	tx_base = core_mmu_get_va(TME_QMP_LITE_INBOUND_MBOX_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_MBOX_REGION_SIZE);
	if (!tx_base) {
		EMSG("mbox_plat: failed to map TX mbox at pa 0x%" PRIxPA,
		     TME_QMP_LITE_INBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	rx_base = core_mmu_get_va(TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_MBOX_REGION_SIZE);
	if (!rx_base) {
		EMSG("mbox_plat: failed to map RX mbox at pa 0x%" PRIxPA,
		     TME_QMP_LITE_OUTBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	irq_reg = core_mmu_get_va(TME_QMP_LITE_IRQ_OUT_REG_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_IRQ_OUT_REG_SIZE);
	if (!irq_reg) {
		EMSG("mbox_plat: failed to map IRQ-out reg at pa 0x%" PRIxPA,
		     TME_QMP_LITE_IRQ_OUT_REG_ADDR);
		return TEE_ERROR_GENERIC;
	}

	tme_qmp_lite_cfg.local_desc_base = tx_base;
	tme_qmp_lite_cfg.remote_desc_base = rx_base;
	tme_qmp_lite_cfg.local_mbox_size = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_mbox_size = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_signal.reg = irq_reg;
	tme_qmp_lite_cfg.remote_signal.value = TME_QMP_LITE_IRQ_OUT_BIT_MASK;

	mbox_channels[0].transport_cfg = &tme_qmp_lite_cfg;

	DMSG("mbox_plat: TX va=0x%" PRIxVA " RX va=0x%" PRIxVA
	     " IRQ-out va=0x%" PRIxVA, tx_base, rx_base, irq_reg);

	return TEE_SUCCESS;
}

const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void)
{
	if (!mbox_channels[0].transport_cfg)
		return NULL;

	return &mbox_plat_data;
}

early_init(plat_qcom_mbox_init);
