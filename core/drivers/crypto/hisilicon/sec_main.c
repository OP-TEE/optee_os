// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2024 HiSilicon Limited.
 * Kunpeng hardware accelerator SEC module init.
 */

#include <initcall.h>
#include <io.h>
#include <malloc.h>
#include <sec_main.h>
#include <sys/queue.h>
#include <trace.h>
#include <util.h>

#define AM_CFG_SINGLE_PORT_MAX_TRANS	0x300014
#define SEC_CORE_INT_MASK		0x301000
#define SEC_CORE_INT_SOURCE		0x301010
#define SEC_RAS_CE_ENABLE		0x301050
#define SEC_RAS_FE_ENABLE		0x301054
#define SEC_RAS_NFE_ENABLE		0x301058
#define SEC_MEM_START_INIT		0x301100
#define SEC_MEM_INIT_DONE		0x301104
#define SEC_CONTROL_REG			0x301200
#define SEC_INTERFACE_USER_CTRL0	0x301220
#define SEC_INTERFACE_USER_CTRL1	0x301224
#define SEC_SAA_EN			0x301270
#define SEC_BD_ERR_CHK_EN0		0x301380
#define SEC_BD_ERR_CHK_EN1		0x301384
#define SEC_BD_ERR_CHK_EN2		0x301388
#define SEC_BD_ERR_CHK_EN3		0x30138c
#define SEC_DYNAMIC_GATE_V3		0x30121c
#define SEC_BD_ERR_CHK_EN2_V3		0x301508
#define SEC_CORE_AUTO_GATE_V3		0x30212c
#define SEC_INTERFACE_USER_CTRL0_V3	0x302220
#define SEC_INTERFACE_USER_CTRL1_V3	0x302224
#define SEC_SINGLE_PORT_MAX_TRANS	0x2060
#define SEC_ABNML_INT_DISABLE		0x0
#define SEC_RAS_CE_ENB_MASK		0x88
#define SEC_RAS_FE_ENB			0x0
#define SEC_RAS_NFE_ENB_MASK		0x177
#define SEC_CLK_GATE_ENABLE		BIT(3)
#define SEC_DYNAMIC_GATE_EN		0x7bff
#define SEC_CORE_AUTO_GATE_EN		GENMASK_32(3, 0)
#define SEC_TRNG_EN_MASK		BIT(8)
#define SEC_SAA_ENABLE			0x17f
#define SEC_SAA_ENABLE_V3		0xf
#define SEC_BD_ERR_CHK0			0xefffffff
#define SEC_BD_ERR_CHK1			0x7ffff7fd
#define SEC_BD_ERR_CHK2			0xffff7fff
#define SEC_BD_ERR_CHK3			0xffffbfff
#define SEC_USER0_CFG			0x20200
#define SEC_USER0_SMMU_NORMAL		(BIT(23) | BIT(15))
#define SEC_USER1_CFG			0x12141214
#define SEC_USER1_SMMU_NORMAL		(BIT(31) | BIT(23) | BIT(15) | BIT(7))
#define SEC_USER0_CFG_V3		0x20200
#define SEC_USER1_CFG_V3		0x8c494

static SLIST_HEAD(, acc_device) sec_list = SLIST_HEAD_INITIALIZER(sec_list);

struct hisi_qp *sec_create_qp(uint8_t sq_type)
{
	struct acc_device *sec_dev = NULL;
	struct acc_device *cur_dev = NULL;
	uint32_t free_qp_num = 0;
	uint32_t max_qp_num = 0;

	/* Find the SEC device with the most remaining qp numbers */
	SLIST_FOREACH(cur_dev, &sec_list, link) {
		if (cur_dev->qm.fun_type == HISI_QM_HW_PF)
			free_qp_num = HISI_QM_PF_Q_NUM - cur_dev->qm.qp_in_used;
		else
			free_qp_num = HISI_QM_VF_Q_NUM - cur_dev->qm.qp_in_used;
		if (free_qp_num > max_qp_num) {
			max_qp_num = free_qp_num;
			sec_dev = cur_dev;
		}
	}

	if (!sec_dev) {
		EMSG("No available sec device");
		return NULL;
	}

	return hisi_qm_create_qp(&sec_dev->qm, sq_type);
}

static void sec_enable_clock_gate(struct hisi_qm *qm)
{
	if (qm->version == HISI_QM_HW_V2)
		return;

	io_setbits32(qm->io_base + SEC_CONTROL_REG, SEC_CLK_GATE_ENABLE);
	io_write32(qm->io_base + SEC_DYNAMIC_GATE_V3, SEC_DYNAMIC_GATE_EN);
	io_write32(qm->io_base + SEC_CORE_AUTO_GATE_V3, SEC_CORE_AUTO_GATE_EN);
}

static enum hisi_drv_status sec_engine_init(struct acc_device *sec_dev)
{
	struct hisi_qm *qm = &sec_dev->qm;
	uint32_t val = 0;

	if (qm->fun_type == HISI_QM_HW_VF)
		return HISI_QM_DRVCRYPT_NO_ERR;

	/* QM_HW_V2 version need to close clock gating */
	io_clrbits32(qm->io_base + SEC_CONTROL_REG, SEC_CLK_GATE_ENABLE);

	hisi_qm_dev_init(qm);

	io_write32(qm->io_base + SEC_MEM_START_INIT, 0x1);
	if (IO_READ32_POLL_TIMEOUT(qm->io_base + SEC_MEM_INIT_DONE, val,
				   val & 0x1, POLL_PERIOD, POLL_TIMEOUT)) {
		EMSG("Fail to init sec mem");
		return HISI_QM_DRVCRYPT_ETMOUT;
	}

	io_setbits32(qm->io_base + SEC_CONTROL_REG, sec_dev->endian);

	if (qm->version == HISI_QM_HW_V2) {
		/* SMMU bypass */
		io_write32(qm->io_base + SEC_INTERFACE_USER_CTRL0,
			   SEC_USER0_CFG);
		io_write32(qm->io_base + SEC_INTERFACE_USER_CTRL1,
			   SEC_USER1_CFG);
		io_write32(qm->io_base + AM_CFG_SINGLE_PORT_MAX_TRANS,
			   SEC_SINGLE_PORT_MAX_TRANS);
		io_write32(qm->io_base + SEC_SAA_EN, SEC_SAA_ENABLE);
		/* HW V2 enable SM4 extra mode, as CTR/ECB */
		io_write32(qm->io_base + SEC_BD_ERR_CHK_EN0, SEC_BD_ERR_CHK0);
		/* Enable SM4 xts mode multiple iv */
		io_write32(qm->io_base + SEC_BD_ERR_CHK_EN1, SEC_BD_ERR_CHK1);
		/* disable PBKDF2 len check */
		io_write32(qm->io_base + SEC_BD_ERR_CHK_EN2, SEC_BD_ERR_CHK2);
		io_write32(qm->io_base + SEC_BD_ERR_CHK_EN3, SEC_BD_ERR_CHK3);
	} else {
		/* cmd_type is controlled by HAC subctrl, default normal */
		io_write32(qm->io_base + SEC_INTERFACE_USER_CTRL0_V3,
			   SEC_USER0_CFG_V3);
		io_write32(qm->io_base + SEC_INTERFACE_USER_CTRL1_V3,
			   SEC_USER1_CFG_V3);
		io_write32(qm->io_base + SEC_SAA_EN, SEC_SAA_ENABLE_V3);
		/* disable PBKDF2 salt len check */
		io_write32(qm->io_base + SEC_BD_ERR_CHK_EN2_V3,
			   SEC_BD_ERR_CHK2);
	}
	io_write32(qm->io_base + SEC_RAS_CE_ENABLE, SEC_RAS_CE_ENB_MASK);
	io_write32(qm->io_base + SEC_RAS_FE_ENABLE, SEC_RAS_FE_ENB);
	io_write32(qm->io_base + SEC_RAS_NFE_ENABLE, SEC_RAS_NFE_ENB_MASK);
	io_write32(qm->io_base + SEC_CORE_INT_MASK, SEC_ABNML_INT_DISABLE);

	sec_enable_clock_gate(qm);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_dev_status_check(struct hisi_qm *qm)
{
	uint32_t val = 0;

	val = io_read32(qm->io_base + SEC_CORE_INT_SOURCE);
	if (val & SEC_RAS_NFE_ENB_MASK) {
		EMSG("SEC NFE RAS happened, need to reset");
		return HISI_QM_DRVCRYPT_HW_EACCESS;
	}

	val = io_read32(qm->io_base + HISI_QM_ABNML_INT_SRC);
	if (val) {
		if (val & HISI_QM_SEC_NFE_INT_MASK)
			EMSG("QM NFE RAS happened, need to reset");

		if (val & HISI_QM_INVALID_DB) {
			EMSG("QM invalid db happened, please check");
			io_write32(qm->io_base + HISI_QM_ABNML_INT_SRC,
				   HISI_QM_INVALID_DB);
		}

		return HISI_QM_DRVCRYPT_HW_EACCESS;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status sec_qm_init(struct acc_device *sec_dev)
{
	struct hisi_qm *qm = &sec_dev->qm;

	qm->io_base = (vaddr_t)phys_to_virt_io(sec_dev->io_base,
						 sec_dev->io_size);
	if (!qm->io_base) {
		EMSG("Fail to get qm io_base");
		return HISI_QM_DRVCRYPT_EFAULT;
	}

	qm->fun_type = sec_dev->fun_type;
	qm->vfs_num = sec_dev->vfs_num;
	qm->sqe_size = SEC_SQE_SIZE;
	qm->sqe_log2_size = SEC_SQE_LOG2_SIZE;
	if (qm->fun_type == HISI_QM_HW_PF) {
		hisi_qm_get_version(qm);
		DMSG("SEC hardware version is %#"PRIx32, qm->version);
		qm->qp_base = HISI_QM_PF_Q_BASE;
		qm->qp_num = HISI_QM_PF_Q_NUM;
		qm->dev_status_check = sec_dev_status_check;
	}

	return hisi_qm_init(qm);
}

static struct acc_device *sec_alloc(void)
{
	struct acc_device *sec_dev = NULL;

	sec_dev = calloc(1, sizeof(*sec_dev));
	if (!sec_dev) {
		EMSG("Fail to alloc sec_dev");
		return NULL;
	}

	sec_dev->io_base = SEC_BAR;
	sec_dev->io_size = SEC_SIZE;
	sec_dev->fun_type = HISI_QM_HW_PF;
	SLIST_INSERT_HEAD(&sec_list, sec_dev, link);

	return sec_dev;
}

static void sec_free(struct acc_device *sec_dev)
{
	SLIST_REMOVE_HEAD(&sec_list, link);
	free(sec_dev);
}

static TEE_Result sec_probe(void)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct acc_device *sec_dev = NULL;
	struct hisi_qm *qm = NULL;

	DMSG("SEC driver init start");
	sec_dev = sec_alloc();
	if (!sec_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	qm = &sec_dev->qm;
	ret = sec_qm_init(sec_dev);
	if (ret) {
		EMSG("Fail to init sec qm, ret=%d", ret);
		goto err_with_pre_init;
	}

	ret = sec_engine_init(sec_dev);
	if (ret) {
		EMSG("fail to init engine, ret=%d", ret);
		goto err_with_qm_init;
	}

	ret = hisi_qm_start(qm);
	if (ret) {
		EMSG("Fail to start qm, ret=%d", ret);
		goto err_with_qm_init;
	}

	DMSG("SEC driver init done");
	return TEE_SUCCESS;

err_with_qm_init:
	hisi_qm_uninit(qm);
err_with_pre_init:
	sec_free(sec_dev);

	return TEE_ERROR_BAD_STATE;
}

driver_init(sec_probe);
