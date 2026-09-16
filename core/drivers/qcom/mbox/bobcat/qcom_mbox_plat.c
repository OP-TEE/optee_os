// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * TME_QMP_LITE_{INBOUND,OUTBOUND}_MBOX_ADDR are named from the TME's point of
 * view: INBOUND is what the TME reads (our TX mailbox), OUTBOUND is what it
 * writes (our RX mailbox). Each starts with the 4-byte QMP-Lite descriptor
 * register, followed by the payload.
 */

#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "qcom_mbox_private.h"
#include "qcom_mbox_qmp_lite.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_INBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_IRQ_OUT_REG_ADDR,
			CORE_MMU_PGDIR_SIZE);

static bool mbox_initialized;

static struct qcom_mbox_qmp_lite_config tme_qmp_lite_cfg;
static struct qcom_mbox_qmp_lite_priv   tme_qmp_lite_priv;

/*
 * transport_cfg is filled in by plat_qcom_mbox_init() once the physical
 * regions have been mapped.
 */
static struct qcom_mbox_chan_config mbox_configs[] = {
	{
		.name           = "tme-qmp-lite",
		.ops            = &qcom_mbox_qmp_lite_ops,
		.transport_cfg  = NULL,
		.transport_priv = &tme_qmp_lite_priv,
	},
};

static struct qcom_mbox_chan_slot mbox_slots[ARRAY_SIZE(mbox_configs)];

static const struct qcom_mbox_plat_data mbox_plat_data = {
	.configs      = mbox_configs,
	.slots        = mbox_slots,
	.num_channels = ARRAY_SIZE(mbox_configs),
};

static TEE_Result plat_qcom_mbox_init(void)
{
	vaddr_t tx_base = 0;
	vaddr_t rx_base = 0;
	vaddr_t irq_reg = 0;

	if (mbox_initialized)
		return TEE_SUCCESS;

	tx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_INBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!tx_base) {
		EMSG("mbox_plat: failed to map TX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_INBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	rx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!rx_base) {
		EMSG("mbox_plat: failed to map RX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_OUTBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	irq_reg = (vaddr_t)phys_to_virt(TME_QMP_LITE_IRQ_OUT_REG_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!irq_reg) {
		EMSG("mbox_plat: failed to map IRQ-out reg at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_IRQ_OUT_REG_ADDR);
		return TEE_ERROR_GENERIC;
	}

	tme_qmp_lite_cfg.local_desc_base     = tx_base;
	tme_qmp_lite_cfg.remote_desc_base    = rx_base;
	tme_qmp_lite_cfg.local_mbox_size     = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_mbox_size    = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_signal.reg   = irq_reg;
	tme_qmp_lite_cfg.remote_signal.value = TME_QMP_LITE_IRQ_OUT_BIT_MASK;

	mbox_configs[0].transport_cfg = &tme_qmp_lite_cfg;
	mbox_initialized = true;

	DMSG("mbox_plat: TX va=0x%08lx RX va=0x%08lx IRQ-out va=0x%08lx",
	     (unsigned long)tx_base, (unsigned long)rx_base,
	     (unsigned long)irq_reg);

	return TEE_SUCCESS;
}

const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void)
{
	/*
	 * A caller may get here before the driver-init phase has run, so
	 * initialise on demand; plat_qcom_mbox_init() is idempotent.
	 */
	if (!mbox_initialized) {
		TEE_Result res = plat_qcom_mbox_init();

		if (res != TEE_SUCCESS) {
			EMSG("mbox_plat: lazy init failed: %#x", res);
			return NULL;
		}
	}

	return &mbox_plat_data;
}

driver_init(plat_qcom_mbox_init);
