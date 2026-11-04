// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include "clk_pas.h"
#include "clock_group.h"

register_phys_mem(MEM_AREA_IO_NSEC, AOSS_CC_BASE, AOSS_CC_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, MPM_SSCAON_BASE, MPM_SSCAON_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TCSR_REGS_BASE, TCSR_REGS_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, LPASS_BASE, LPASS_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, TURING_BASE, TURING_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, LPASS_AUDIO_CC_BASE, LPASS_AUDIO_CC_SIZE);

#define AUDIO_CORE_TIMEOUT_US			10000
#define AUDIO_CORE_GDSC_OFF_TIMEOUT_US		100
/* Consecutive idle reads of the QHS QChannel needed before a collapse */
#define QHS_IDLE_READS				20

/*
 * Halt the bus master port of TCSR halt block @halt, @name in messages;
 * the restart that follows runs either way.
 */
static void halt_port(vaddr_t halt, const char *name)
{
	if (qcom_q6_halt(halt + TCSR_HALTREQ, halt + TCSR_HALTACK))
		EMSG("%s halt not acknowledged", name);
}

/* Turn on the QDSP6SS clocks the boot FSM needs, before it is started */
static void q6ss_clocks_enable(vaddr_t q6ss)
{
	io_setbits32(q6ss + QDSP6SS_XO_CBCR, QDSP6SS_CBCR_CLKEN);
	io_setbits32(q6ss + QDSP6SS_SLEEP_CBCR, QDSP6SS_CBCR_CLKEN);
	io_setbits32(q6ss + QDSP6SS_CORE_CBCR, QDSP6SS_CBCR_CLKEN);
}

static TEE_Result lpass_enable(void)
{
	vaddr_t gcc = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t lpass = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t mpm = QCOM_IO_VA(MPM_SSCAON_BASE, MPM_SSCAON_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !lpass || !mpm)
		return TEE_ERROR_GENERIC;

	/* Release the clamp on the SSC power-domain handshakes */
	io_clrbits32(mpm + MPM_SSCAON_CONFIG1, MPM_SSCAON_CONFIG1_CLAMP);

	io_setbits32(gcc + GCC_SSC_RESET, GCC_SSC_RESET_SSC_ARES);
	udelay(1);
	io_clrbits32(gcc + GCC_SSC_RESET, GCC_SSC_RESET_SSC_ARES);

	/* SSC interface clocks sourced by GCC */
	res = qcom_clock_enable_cbc(gcc + GCC_LPASS_Q6_AXI_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(gcc + GCC_LPASS_CORE_AXIM_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(gcc + GCC_LPASS_SWAY_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(gcc + GCC_SSC_CNOC_MPU_CBCR);
	if (res)
		return res;

	/* QDSP6 bus and debug clocks */
	res = qcom_clock_enable_cbc(lpass + SSC_SCC_Q6_AHBS_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(lpass + SSC_SCC_Q6_AHBM_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(lpass + SSC_SCC_AT_CBCR);
	if (res)
		return res;
	res = qcom_clock_enable_cbc(lpass + SSC_SCC_PCLKDBG_CBCR);
	if (res)
		return res;

	q6ss_clocks_enable(lpass + LPASS_QDSP6SS_OFFSET);

	io_setbits32(mpm + MPM_SSCAON_CONFIG1,
		     MPM_SSCAON_CONFIG1_RETAIN_FF_ENABLE);

	return TEE_SUCCESS;
}

static TEE_Result turing_enable(void)
{
	vaddr_t gcc = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t turing = QCOM_IO_VA(TURING_BASE, TURING_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !turing)
		return TEE_ERROR_GENERIC;

	/* Config NoC slave port, disconnected by the last shutdown */
	res = qcom_clock_enable_cbc(gcc + GCC_TURING_CFG_AHB_CBCR);
	if (res)
		return res;

	res = qcom_clock_enable_cbc(turing + TURING_WRAPPER_AON_CBCR);
	if (res)
		return res;

	/* AHB-AON clock root from XO; the root takes a new source on UPDATE */
	res = qcom_clock_set_rate(turing + TURING_AON_CFG_RCGR,
				  turing + TURING_AON_CMD_RCGR,
				  io_read32(turing + TURING_AON_CFG_RCGR) &
				  ~RCGR_SRC_SEL_MASK);
	if (res)
		return res;

	res = qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBS_AON_CBCR);
	if (res)
		return res;

	res = qcom_clock_enable_cbc(turing + TURING_Q6SS_AHBM_AON_CBCR);
	if (res)
		return res;

	q6ss_clocks_enable(turing + TURING_QDSP6SS_OFFSET);

	return TEE_SUCCESS;
}

/*
 * Make the QHS QChannel of the LPASS core accept a request the NoC keeps
 * denying, by overriding it.
 */
static TEE_Result lpass_qhs_override(vaddr_t qhs)
{
	uint64_t timeout = 0;

	io_clrbits32(qhs, QCHANNEL_CTL_QREQN);
	io_setbits32(qhs, QCHANNEL_CTL_OVERRIDE_EN);
	io_setbits32(qhs, QCHANNEL_CTL_QREQN);
	udelay(10);
	io_clrbits32(qhs, QCHANNEL_CTL_QREQN);

	timeout = timeout_init_us(AUDIO_CORE_TIMEOUT_US);
	while (io_read32(qhs) & QCHANNEL_CTL_ACCEPTN) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		io_setbits32(qhs, QCHANNEL_CTL_QREQN);
		udelay(10);
		io_clrbits32(qhs, QCHANNEL_CTL_QREQN);
		udelay(5);
	}

	return TEE_SUCCESS;
}

/*
 * Retry a power collapse of the LPASS core that the GDS hardware control
 * aborted because the QHS QChannel denied it.
 */
static TEE_Result lpass_audio_core_recollapse(vaddr_t lpass)
{
	vaddr_t gdscr = lpass + SSC_SCC_AUDIO_CORE_GDSCR;
	vaddr_t qhs = lpass + SSC_SCC_LPASS_CORE_QHS_QCHANNEL_CTL;
	vaddr_t irq = lpass + SSC_SCC_LPASS_AON_GDS_HW_CTRL_IRQ_STATUS;
	TEE_Result res = TEE_SUCCESS;
	uint32_t val = 0;

	res = lpass_qhs_override(qhs);
	if (res)
		return res;

	io_clrbits32(gdscr, GDSCR_SW_COLLAPSE);
	io_write32(lpass + SSC_SCC_LPASS_AON_GDS_HW_CTRL_IRQ_CLEAR,
		   GDS_HW_CTRL_IRQ_BIT);
	if (IO_READ32_POLL_TIMEOUT(irq, val, !(val & GDS_HW_CTRL_IRQ_BIT), 1,
				   AUDIO_CORE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	io_setbits32(gdscr, GDSCR_SW_COLLAPSE);
	if (IO_READ32_POLL_TIMEOUT(gdscr, val, !(val & GDSCR_PWR_ON), 1,
				   AUDIO_CORE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	io_clrbits32(qhs, QCHANNEL_CTL_OVERRIDE_EN);

	return TEE_SUCCESS;
}

/*
 * The LPASS core (audio) sits in the SSC next to the ADSP, behind its own
 * GDSC and LPASS NoC QChannels. If the ADSP left it on, halt its NoC ports
 * and power collapse it before the SSC restart.
 */
static TEE_Result lpass_audio_core_collapse(vaddr_t lpass, vaddr_t audio_cc)
{
	vaddr_t gdscr = lpass + SSC_SCC_AUDIO_CORE_GDSCR;
	vaddr_t qhm = lpass + SSC_SCC_LPASS_CORE_QHM_QCHANNEL_CTL;
	vaddr_t qhs = lpass + SSC_SCC_LPASS_CORE_QHS_QCHANNEL_CTL;
	TEE_Result res = TEE_SUCCESS;
	unsigned int idle = 0;
	uint64_t timeout = 0;
	uint32_t val = 0;

	if (!(io_read32(gdscr) & GDSCR_PWR_ON))
		return TEE_SUCCESS;

	res = qcom_clock_enable_cbc(lpass + SSC_SCC_RO_CBCR);
	if (res)
		return res;

	io_setbits32(gdscr, GDSCR_RETAIN_FF_ENABLE);

	res = qcom_clock_enable_cbc(audio_cc +
				    LPASS_AUDIO_CORE_SYSNOC_MPORT_CORE_CBCR);
	if (res)
		return res;

	/* Halt the master port, re-requesting while the NoC denies it */
	if (IO_READ32_POLL_TIMEOUT(qhm, val, !(val & QCHANNEL_CTL_ACTIVE), 1,
				   AUDIO_CORE_TIMEOUT_US))
		return TEE_ERROR_TIMEOUT;

	io_clrbits32(qhm, QCHANNEL_CTL_QREQN);
	udelay(1);

	timeout = timeout_init_us(AUDIO_CORE_TIMEOUT_US);
	while (io_read32(qhm) & QCHANNEL_CTL_ACCEPTN) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
		if (io_read32(qhm) & QCHANNEL_CTL_DENY)
			io_setbits32(qhm, QCHANNEL_CTL_QREQN);
		io_clrbits32(qhm, QCHANNEL_CTL_QREQN);
		udelay(1);
	}

	timeout = timeout_init_us(AUDIO_CORE_TIMEOUT_US);
	while (idle < QHS_IDLE_READS) {
		if (io_read32(qhs) & QCHANNEL_CTL_ACTIVE)
			idle = 0;
		else
			idle++;
		if (timeout_elapsed(timeout))
			return TEE_ERROR_TIMEOUT;
	}

	io_setbits32(gdscr, GDSCR_SW_COLLAPSE);
	if (!IO_READ32_POLL_TIMEOUT(gdscr, val, !(val & GDSCR_PWR_ON), 1,
				    AUDIO_CORE_GDSC_OFF_TIMEOUT_US))
		return TEE_SUCCESS;

	if ((io_read32(lpass + SSC_SCC_LPASS_AON_GDS_HW_CTRL_IRQ_STATUS) &
	     GDS_HW_CTRL_IRQ_BIT) && (io_read32(qhs) & QCHANNEL_CTL_DENY))
		return lpass_audio_core_recollapse(lpass);

	/* Release the slave port so that it cannot hold off the restart */
	res = lpass_qhs_override(qhs);
	if (res)
		return res;

	return TEE_ERROR_TIMEOUT;
}

/*
 * Put the SSC, which holds the ADSP, through a subsystem restart, so that a
 * stopped or crashed ADSP boots again from reset.
 */
static TEE_Result lpass_reset_processor(void)
{
	vaddr_t gcc = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t lpass = QCOM_IO_VA(LPASS_BASE, LPASS_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t pdc = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t audio_cc = QCOM_IO_VA(LPASS_AUDIO_CC_BASE, LPASS_AUDIO_CC_SIZE);
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !lpass || !aoss_cc || !pdc || !tcsr || !audio_cc)
		return TEE_ERROR_GENERIC;

	/* The QDSP6SS registers are reachable only with this branch on */
	res = qcom_clock_enable_cbc(gcc + GCC_LPASS_SWAY_CBCR);
	if (res)
		return res;

	/* Best effort, as the halts below: the restart has to happen anyway */
	res = lpass_audio_core_collapse(lpass, audio_cc);
	if (res)
		EMSG("LPASS core power collapse failed: %#"PRIx32, res);

	/* Reset the retention flops with the core */
	io_setbits32(lpass + LPASS_QDSP6SS_OFFSET + QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA);

	if ((io_read32(tcsr + TCSR_SSC_PWR_ON) & TCSR_HALT_BIT) &&
	    !(io_read32(tcsr + TCSR_LPASS_HALT + TCSR_MASTER_IDLE) &
	      TCSR_HALT_BIT))
		halt_port(tcsr + TCSR_LPASS_HALT, "ADSP");

	halt_port(tcsr + TCSR_LPASS_CORE_AXIM_HALT, "LPASS core AXIM");

	io_setbits32(pdc + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_SENSORS_BIT);
	io_setbits32(aoss_cc + AOSS_CC_SENSORS_RESTART, AOSS_CC_SS_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(pdc + RPMH_PDC_SYNC_RESET,
		     PDC_SYNC_RESET_AUDIO_SENSORS_BIT);
	io_clrbits32(aoss_cc + AOSS_CC_SENSORS_RESTART, AOSS_CC_SS_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(tcsr + TCSR_LPASS_HALT + TCSR_HALTREQ, TCSR_HALT_BIT);
	io_clrbits32(tcsr + TCSR_LPASS_CORE_AXIM_HALT + TCSR_HALTREQ,
		     TCSR_HALT_BIT);

	return TEE_SUCCESS;
}

/*
 * Put Turing, which holds the CDSP, through a subsystem restart and drop the
 * CX iPeak limits management vote the CDSP may have left behind.
 */
static TEE_Result turing_reset_processor(void)
{
	vaddr_t gcc = QCOM_IO_VA(GCC_BASE, GCC_SIZE);
	vaddr_t turing = QCOM_IO_VA(TURING_BASE, TURING_SIZE);
	vaddr_t aoss_cc = QCOM_IO_VA(AOSS_CC_BASE, AOSS_CC_SIZE);
	vaddr_t pdc = QCOM_IO_VA(RPMH_PDC_GLOBAL_BASE, RPMH_PDC_GLOBAL_SIZE);
	vaddr_t tcsr = QCOM_IO_VA(TCSR_MUTEX_BASE, TCSR_MUTEX_SIZE);
	vaddr_t tcsr_regs = QCOM_IO_VA(TCSR_REGS_BASE, TCSR_REGS_SIZE);
	vaddr_t halt = tcsr + TCSR_TURING_HALT;
	TEE_Result res = TEE_SUCCESS;

	if (!gcc || !turing || !aoss_cc || !pdc || !tcsr || !tcsr_regs)
		return TEE_ERROR_GENERIC;

	/* The QDSP6SS registers are reachable only with this branch on */
	res = qcom_clock_enable_cbc(gcc + GCC_TURING_CFG_AHB_CBCR);
	if (res)
		return res;

	/* Reset the retention flops with the core */
	io_setbits32(turing + TURING_QDSP6SS_OFFSET + QDSP6SS_RET_CFG,
		     QDSP6SS_RET_CFG_RET_ARES_ENA);

	/* Halt config NoC traffic by disconnecting the slave port */
	io_clrbits32(gcc + GCC_TURING_CFG_AHB_CBCR, CBCR_BRANCH_ENABLE_BIT);

	/*
	 * TCSR_TURING_PWR_ON only says whether the bus master port can be
	 * halted: a core released moments ago runs with it still clear, so
	 * the restart below must not depend on it.
	 */
	if ((io_read32(halt + TCSR_TURING_PWR_ON) & TCSR_HALT_BIT) &&
	    !(io_read32(halt + TCSR_MASTER_IDLE) & TCSR_HALT_BIT))
		halt_port(halt, "CDSP");

	io_setbits32(pdc + RPMH_PDC_SYNC_RESET, PDC_SYNC_RESET_COMPUTE_BIT);
	io_setbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     AOSS_CC_SS_RESTART_BIT);
	dsb();
	udelay(200);

	io_clrbits32(halt + TCSR_HALTREQ, TCSR_HALT_BIT);
	io_clrbits32(pdc + RPMH_PDC_SYNC_RESET, PDC_SYNC_RESET_COMPUTE_BIT);
	io_clrbits32(aoss_cc + AOSS_CC_COMPUTESS_RESTART,
		     AOSS_CC_SS_RESTART_BIT);
	dsb();
	udelay(200);

	io_write32(tcsr_regs + TCSR_CXIP_LM_FNT_CLEAR,
		   TCSR_CXIP_LM_FNT_CLEAR_ALL);
	udelay(1);
	if (io_read32(tcsr_regs + TCSR_CXIP_LM_FNT_STATUS)) {
		EMSG("CX iPeak vote not cleared");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_clock_enable_pas_processor(enum qcom_clk_group group __unused)
{
	/* The DSP core is released entirely within the PTA fw_start path. */
	return TEE_SUCCESS;
}

TEE_Result qcom_clock_pas_reset(enum qcom_clk_group group)
{
	switch (group) {
	case QCOM_CLKS_LPASS:
		return lpass_reset_processor();
	case QCOM_CLKS_TURING:
		return turing_reset_processor();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result qcom_clock_enable_pas(enum qcom_clk_group group)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (group) {
	case QCOM_CLKS_LPASS:
		res = lpass_enable();
		break;
	case QCOM_CLKS_TURING:
		res = turing_enable();
		break;
	default:
		EMSG("Unsupported clock group %d", group);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (res)
		EMSG("Failed to enable clock group %d: %#"PRIx32, group, res);

	return res;
}
