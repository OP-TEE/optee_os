// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 HiSilicon Limited.
 * Kunpeng hardware accelerator queue management module.
 */
#include "hisi_qm.h"

#define QM_FVT_CFG_RDY_BIT	0x1
/* Doorbell */
#define QM_DOORBELL_SQ_CQ_BASE	0x1000
#define QM_DB_CMD_SHIFT		12
#define QM_DB_RAND_DATA_SHIFT	16
#define QM_DB_INDEX_SHIFT	32
#define QM_DB_PRIORITY_SHIFT	48
#define QM_DB_RAND_DATA		0x5a
#define QM_DOORBELL_CMD_SQ	0
#define QM_DOORBELL_CMD_CQ	1
/* Mailbox */
#define QM_MAILBOX_BASE		0x300
#define QM_MAILBOX_DATA_ADDR_L	0x304
#define QM_MAILBOX_DATA_ADDR_H	0x308
#define QM_MB_BUSY_SHIFT	13
#define QM_MB_BUSY_BIT		BIT32(QM_MB_BUSY_SHIFT)
#define QM_MB_OP_SHIFT		14
#define QM_MB_OP_WR		0
#define QM_MB_OP_RD		1
#define QM_MB_STATUS_MASK	GENMASK_32(12, 9)
#define QM_MB_WAIT_READY_CNT	10
#define QM_MB_WAIT_MAX_CNT	21000
#define QM_MB_WAIT_PERIOD	200
/* XQC_VFT */
#define QM_VFT_CFG_OP_ENABLE	0x100054
#define QM_VFT_CFG_OP_WR	0x100058
#define QM_VFT_CFG_TYPE		0x10005c
#define QM_VFT_CFG_ADDRESS	0x100060
#define QM_VFT_CFG_DATA_L	0x100064
#define QM_VFT_CFG_DATA_H	0x100068
#define QM_VFT_CFG_RDY		0x10006c
#define QM_SQC_VFT		0
#define QM_CQC_VFT		1
#define QM_SQC_VFT_START_SQN_SHIFT 28
#define QM_SQC_VFT_VALID	BIT64(44)
#define QM_SQC_VFT_SQ_NUM_SHIFT 45
#define QM_CQC_VFT_VALID	BIT(28)
#define QM_VFT_WRITE		0
#define QM_VFT_READ		1
#define QM_SQC_VFT_BASE_MASK	0x3ff
#define QM_SQC_VFT_NUM_MASK	0x3ff
/* QM INIT */
#define QM_MEM_START_INIT	0x100040
#define QM_MEM_INIT_DONE	0x100044
#define QM_VF_AEQ_INT_MASK	0x4
#define QM_VF_AEQ_INT_MASK_EN	0x1
#define QM_VF_EQ_INT_MASK	0xc
#define QM_VF_EQ_INT_MASK_EN	0x1
#define QM_ARUSER_M_CFG_1	0x100088
#define QM_ARUSER_M_CFG_ENABLE	0x100090
#define QM_AWUSER_M_CFG_1	0x100098
#define QM_AWUSER_M_CFG_ENABLE	0x1000a0
#define QM_AXUSER_CFG		0x40001070
#define AXUSER_M_CFG_ENABLE	0x7ffffc
#define QM_AXI_M_CFG		0x1000ac
#define AXI_M_CFG		0xffff
#define QM_PEH_AXUSER_CFG	0x1000cc
#define PEH_AXUSER_CFG		0x400801
#define QM_CACHE_CTL		0x100050
#define QM_CACHE_CFG		0x4893
#define QM_CACHE_WB_START	0x204
#define QM_CACHE_WB_DONE	0x208
#define QM_PM_CTRL0		0x100148
#define QM_IDLE_DISABLE		BIT(9)
#define QM_DB_TIMEOUT_CFG	0x100074
#define QM_DB_TIMEOUT_SET	0x1fffff
/* XQC shift */
#define QM_SQ_SQE_SIZE_SHIFT	12
#define QM_SQ_ORDER_SHIFT	4
#define QM_SQ_TYPE_SHIFT	8
#define QM_CQE_SIZE		4
#define QM_CQ_CQE_SIZE_SHIFT	12
/* CQE */
#define QM_CQE_PHASE(cqe) (((cqe)->w7) & QM_FVT_CFG_RDY_BIT)

enum qm_mailbox_common_cmd {
	QM_MB_CMD_SQC = 0x0,
	QM_MB_CMD_CQC,
	QM_MB_CMD_EQC,
	QM_MB_CMD_AEQC,
	QM_MB_CMD_SQC_BT,
	QM_MB_CMD_CQC_BT,
	QM_MB_CMD_SQC_VFT,
};

enum qm_mailbox_cmd_v3 {
	QM_MB_CM_CLOSE_QM = 0x7,
	QM_MB_CMD_CLOSE_QP,
	QM_MB_CMD_FLUSH_QM,
	QM_MB_CMD_FLUSH_QP,
	QM_MB_CMD_SRC = 0xc,
	QM_MB_CMD_DST,
	QM_MB_CMD_STOP_QM,
};

struct qm_mailbox {
	union {
		struct {
			uint16_t w0;
			uint16_t queue;
			uint32_t base_l;
			uint32_t base_h;
			uint32_t token;
		};
		uint64_t x[2];
	};
};

struct qm_dfx_registers {
	const char *reg_name;
	uint32_t reg_offset;
};

static const struct qm_dfx_registers qm_dfx_regs[] = {
	{ .reg_name = "QM_ECC_1BIT_CNT           ", .reg_offset = 0x104000 },
	{ .reg_name = "QM_ECC_MBIT_CNT           ", .reg_offset = 0x104008 },
	{ .reg_name = "QM_DFX_MB_CNT             ", .reg_offset = 0x104018 },
	{ .reg_name = "QM_DFX_DB_CNT             ", .reg_offset = 0x104028 },
	{ .reg_name = "QM_DFX_SQE_CNT            ", .reg_offset = 0x104038 },
	{ .reg_name = "QM_DFX_CQE_CNT            ", .reg_offset = 0x104048 },
	{ .reg_name = "QM_DFX_SEND_SQE_TO_ACC_CNT", .reg_offset = 0x104050 },
	{ .reg_name = "QM_DFX_WB_SQE_FROM_ACC_CNT", .reg_offset = 0x104058 },
	{ .reg_name = "QM_DFX_ACC_FINISH_CNT     ", .reg_offset = 0x104060 },
	{ .reg_name = "QM_DFX_CQE_ERR_CNT        ", .reg_offset = 0x1040b4 },
	{ }
};

void hisi_qm_get_version(struct hisi_qm *qm)
{
	qm->version = io_read32(qm->io_base + HISI_QM_REVISON_ID_BASE) &
		      HISI_QM_REVISON_ID_MASK;
}

static void qm_db(struct hisi_qm *qm, uint16_t qn, uint8_t cmd, uint16_t index,
		  uint8_t priority)
{
	uint64_t doorbell = 0;

	doorbell = qn | SHIFT_U64(cmd, QM_DB_CMD_SHIFT) |
		   SHIFT_U64(QM_DB_RAND_DATA, QM_DB_RAND_DATA_SHIFT) |
		   SHIFT_U64(index, QM_DB_INDEX_SHIFT) |
		   SHIFT_U64(priority, QM_DB_PRIORITY_SHIFT);

	io_write64(qm->io_base + QM_DOORBELL_SQ_CQ_BASE, doorbell);
}

static void qm_mb_write(struct hisi_qm *qm, struct qm_mailbox *mb)
{
	vaddr_t dst = qm->io_base + QM_MAILBOX_BASE;

	write_64bit_pair(dst, mb->x[1], mb->x[0]);
	dsb_osh();
}

static void qm_mb_read(struct hisi_qm *qm, struct qm_mailbox *mb)
{
	vaddr_t mb_base = qm->io_base + QM_MAILBOX_BASE;

	read_64bit_pair(mb_base, mb->x + 1, mb->x);
	dsb_osh();
}

static enum hisi_drv_status qm_wait_mb_ready(struct hisi_qm *qm)
{
	struct qm_mailbox mb = { };
	uint32_t timeout = 0;

	timeout = timeout_init_us(QM_MB_WAIT_PERIOD * QM_MB_WAIT_READY_CNT);
	while (!timeout_elapsed(timeout)) {
		/* 128 bits should be read from hardware at one time*/
		qm_mb_read(qm, &mb);
		if (!(mb.w0 & QM_MB_BUSY_BIT))
			return HISI_QM_DRVCRYPT_NO_ERR;
	}

	EMSG("QM mailbox is busy to start!");

	return HISI_QM_DRVCRYPT_EBUSY;
}

static enum hisi_drv_status qm_wait_mb_finish(struct hisi_qm *qm,
					      struct qm_mailbox *mb)
{
	uint32_t timeout = 0;

	timeout = timeout_init_us(QM_MB_WAIT_PERIOD * QM_MB_WAIT_MAX_CNT);
	while (!timeout_elapsed(timeout)) {
		qm_mb_read(qm, mb);
		if (!(mb->w0 & QM_MB_BUSY_BIT)) {
			if (mb->w0 & QM_MB_STATUS_MASK) {
				EMSG("QM mailbox operation failed!");
				return HISI_QM_DRVCRYPT_EIO;
			} else {
				return HISI_QM_DRVCRYPT_NO_ERR;
			}
		}
	}

	return HISI_QM_DRVCRYPT_ETMOUT;
}

static void qm_mb_init(struct qm_mailbox *mb, uint8_t cmd, uint64_t base,
		       uint16_t qnum, uint8_t op)
{
	mb->w0 = cmd | SHIFT_U32(op, QM_MB_OP_SHIFT) |  QM_MB_BUSY_BIT;
	mb->queue = qnum;
	reg_pair_from_64(base, &mb->base_h, &mb->base_l);
	mb->token = 0;
}

static enum hisi_drv_status qm_mb_nolock(struct hisi_qm *qm,
					 struct qm_mailbox *mb)
{
	if (qm_wait_mb_ready(qm))
		return HISI_QM_DRVCRYPT_EBUSY;

	qm_mb_write(qm, mb);

	return qm_wait_mb_finish(qm, mb);
}

static enum hisi_drv_status hisi_qm_mb_write(struct hisi_qm *qm, uint8_t cmd,
					     uintptr_t dma_addr, uint16_t qnum)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct qm_mailbox mb = { };

	qm_mb_init(&mb, cmd, dma_addr, qnum, QM_MB_OP_WR);
	mutex_lock(&qm->mailbox_lock);
	ret = qm_mb_nolock(qm, &mb);
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static enum hisi_drv_status hisi_qm_mb_read(struct hisi_qm *qm, uint64_t *base,
					    uint8_t cmd, uint16_t qnum)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct qm_mailbox mb = { };

	qm_mb_init(&mb, cmd, 0, qnum, QM_MB_OP_RD);
	mutex_lock(&qm->mailbox_lock);
	ret = qm_mb_nolock(qm, &mb);
	mutex_unlock(&qm->mailbox_lock);
	if (ret)
		return ret;

	reg_pair_from_64(*base, &mb.base_h, &mb.base_l);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void qm_cfg_vft_data(struct hisi_qm *qm, uint8_t vft_type,
			    uint32_t base, uint32_t number)
{
	uint32_t data_h = 0;
	uint32_t data_l = 0;
	uint64_t data = 0;

	switch (vft_type) {
	case QM_SQC_VFT:
		data = SHIFT_U64(base, QM_SQC_VFT_START_SQN_SHIFT) |
			QM_SQC_VFT_VALID |
			SHIFT_U64((number - 1), QM_SQC_VFT_SQ_NUM_SHIFT);
		break;
	case QM_CQC_VFT:
		data = QM_CQC_VFT_VALID;
		break;
	default:
		panic("Invalid vft type");
	}

	reg_pair_from_64(data, &data_h, &data_l);
	io_write32(qm->io_base + QM_VFT_CFG_DATA_L, data_l);
	io_write32(qm->io_base + QM_VFT_CFG_DATA_H, data_h);
}

static enum hisi_drv_status qm_set_vft_common(struct hisi_qm *qm,
					      uint8_t vft_type,
					      uint32_t function,
					      uint32_t base,
					      uint32_t num)
{
	uint32_t val = 0;

	if (IO_READ32_POLL_TIMEOUT(qm->io_base + QM_VFT_CFG_RDY, val,
				   val & QM_FVT_CFG_RDY_BIT, POLL_PERIOD,
				   POLL_TIMEOUT)) {
		EMSG("QM VFT is not ready");
		return HISI_QM_DRVCRYPT_EBUSY;
	}

	io_write32(qm->io_base + QM_VFT_CFG_OP_WR, QM_VFT_WRITE);
	io_write32(qm->io_base + QM_VFT_CFG_TYPE, vft_type);
	io_write32(qm->io_base + QM_VFT_CFG_ADDRESS, function);
	qm_cfg_vft_data(qm, vft_type, base, num);
	io_write32(qm->io_base + QM_VFT_CFG_RDY, 0x0);
	io_write32(qm->io_base + QM_VFT_CFG_OP_ENABLE, QM_FVT_CFG_RDY_BIT);

	if (IO_READ32_POLL_TIMEOUT(qm->io_base + QM_VFT_CFG_RDY, val,
				   val & QM_FVT_CFG_RDY_BIT, POLL_PERIOD,
				   POLL_TIMEOUT)) {
		EMSG("QM VFT is not ready");
		return HISI_QM_DRVCRYPT_EBUSY;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status qm_set_xqc_vft(struct hisi_qm *qm,
					   uint32_t function,
					   uint32_t base, uint32_t num)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	int i = 0;

	for (i = QM_SQC_VFT; i <= QM_CQC_VFT; i++) {
		ret = qm_set_vft_common(qm, i, function, base, num);
		if (ret) {
			EMSG("QM set type %d fail", i);
			return ret;
		}
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status qm_get_vft(struct hisi_qm *qm, uint32_t *base,
				       uint32_t *num)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	uint64_t sqc_vft = 0;

	ret = hisi_qm_mb_read(qm, &sqc_vft, QM_MB_CMD_SQC_VFT, 0);
	if (ret)
		return ret;

	*base = (sqc_vft >> QM_SQC_VFT_START_SQN_SHIFT) & QM_SQC_VFT_BASE_MASK;
	*num = ((sqc_vft >> QM_SQC_VFT_SQ_NUM_SHIFT) & QM_SQC_VFT_NUM_MASK) + 1;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void qp_free(struct hisi_qm *qm, uint32_t id)
{
	struct hisi_qp *qp = &qm->qp_array[id];

	free(qp->sqe);
	free(qp->cqe);
}

static enum hisi_drv_status qp_alloc(struct hisi_qm *qm, uint32_t id)
{
	size_t sq_size = qm->sqe_size * HISI_QM_Q_DEPTH;
	size_t cq_size = sizeof(struct qm_cqe) * HISI_QM_Q_DEPTH;
	struct hisi_qp *qp = &qm->qp_array[id];
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	qp->sqe = memalign(HISI_QM_ALIGN128, sq_size);
	if (!qp->sqe) {
		EMSG("Fail to malloc sq[%"PRIu32"]", id);
		return HISI_QM_DRVCRYPT_ENOMEM;
	}
	qp->sqe_dma = virt_to_phys(qp->sqe);
	qp->cqe = memalign(HISI_QM_ALIGN32, cq_size);
	if (!qp->cqe) {
		EMSG("Fail to malloc cq[%"PRIu32"]", id);
		ret = HISI_QM_DRVCRYPT_ENOMEM;
		goto free_sqe;
	}
	qp->cqe_dma = virt_to_phys(qp->cqe);

	qp->qp_id = id;
	qp->qm = qm;
	return HISI_QM_DRVCRYPT_NO_ERR;

free_sqe:
	free(qp->sqe);
	return ret;
}

static void hisi_qm_free_xqc(struct qm_xqc *xqc)
{
	free(xqc->cqc);
	free(xqc->sqc);
}

static void qm_free(struct hisi_qm *qm)
{
	unsigned int i = 0;

	for (i = 0; i < qm->qp_num; i++)
		qp_free(qm, i);

	free(qm->qp_array);
	hisi_qm_free_xqc(&qm->xqc);
	hisi_qm_free_xqc(&qm->cfg_xqc);
}

static enum hisi_drv_status hisi_qm_alloc_xqc(struct qm_xqc *xqc,
					      uint32_t qp_num)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	size_t sqc_size = 0;
	size_t cqc_size = 0;

	sqc_size = sizeof(struct qm_sqc) * qp_num;
	cqc_size = sizeof(struct qm_cqc) * qp_num;

	xqc->sqc = memalign(HISI_QM_ALIGN32, sqc_size);
	if (!xqc->sqc) {
		EMSG("Fail to malloc sqc");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}
	memset(xqc->sqc, 0, sqc_size);
	xqc->sqc_dma = virt_to_phys(xqc->sqc);

	xqc->cqc = memalign(HISI_QM_ALIGN32, cqc_size);
	if (!xqc->cqc) {
		EMSG("Fail to malloc cqc");
		ret = HISI_QM_DRVCRYPT_ENOMEM;
		goto free_sqc;
	}
	memset(xqc->cqc, 0, cqc_size);
	xqc->cqc_dma = virt_to_phys(xqc->cqc);

	return HISI_QM_DRVCRYPT_NO_ERR;

	free(xqc->cqc);
free_sqc:
	free(xqc->sqc);
	return ret;
}

static enum hisi_drv_status qm_alloc(struct hisi_qm *qm)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	int32_t j;
	uint32_t i;

	ret = hisi_qm_alloc_xqc(&qm->xqc, qm->qp_num);
	if (ret)
		return ret;

	ret = hisi_qm_alloc_xqc(&qm->cfg_xqc, 1);
	if (ret)
		goto free_xqc;

	qm->qp_array = calloc(qm->qp_num, sizeof(struct hisi_qp));
	if (!qm->qp_array) {
		EMSG("Fail to malloc qp_array");
		ret = HISI_QM_DRVCRYPT_ENOMEM;
		goto free_cfg_xqc;
	}

	for (i = 0; i < qm->qp_num; i++) {
		ret = qp_alloc(qm, i);
		if (ret)
			goto free_qp_mem;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;

free_qp_mem:
	for (j = (int)i - 1; j >= 0; j--)
		qp_free(qm, j);
	free(qm->qp_array);
free_cfg_xqc:
	hisi_qm_free_xqc(&qm->cfg_xqc);
free_xqc:
	hisi_qm_free_xqc(&qm->xqc);
	return ret;
}

enum hisi_drv_status hisi_qm_init(struct hisi_qm *qm)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	if (qm->fun_type == HISI_QM_HW_VF) {
		ret = qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
		if (ret) {
			EMSG("Fail to get function vft config");
			return ret;
		}
	}

	if (!qm->qp_num || !qm->sqe_size) {
		EMSG("Invalid QM parameters");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	ret = qm_alloc(qm);
	if (ret)
		return ret;

	qm->qp_in_used = 0;
	qm->qp_idx = 0;
	mutex_init(&qm->qp_lock);
	mutex_init(&qm->mailbox_lock);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void qm_cache_writeback(struct hisi_qm *qm)
{
	uint32_t val = 0;

	io_write32(qm->io_base + QM_CACHE_WB_START, QM_FVT_CFG_RDY_BIT);

	if (IO_READ32_POLL_TIMEOUT(qm->io_base + QM_CACHE_WB_DONE, val,
				   val & QM_FVT_CFG_RDY_BIT, POLL_PERIOD,
				   POLL_TIMEOUT))
		panic("QM writeback sqc cache fail");
}

void hisi_qm_uninit(struct hisi_qm *qm)
{
	qm_cache_writeback(qm);
	qm_free(qm);
	mutex_destroy(&qm->qp_lock);
	mutex_destroy(&qm->mailbox_lock);
}

static enum hisi_drv_status qm_hw_mem_reset(struct hisi_qm *qm)
{
	uint32_t val = 0;

	io_write32(qm->io_base + QM_MEM_START_INIT, QM_FVT_CFG_RDY_BIT);

	if (IO_READ32_POLL_TIMEOUT(qm->io_base + QM_MEM_INIT_DONE, val,
				   val & QM_FVT_CFG_RDY_BIT, POLL_PERIOD,
				   POLL_TIMEOUT))
		return HISI_QM_DRVCRYPT_EBUSY;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status qm_func_vft_cfg(struct hisi_qm *qm)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	uint32_t q_base = qm->qp_num;
	uint32_t act_q_num = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	if (!qm->vfs_num)
		return HISI_QM_DRVCRYPT_NO_ERR;

	if (qm->vfs_num > HISI_QM_MAX_VFS_NUM) {
		EMSG("Invalid QM vfs_num");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	for (i = 1; i <= qm->vfs_num; i++) {
		act_q_num = HISI_QM_VF_Q_NUM;
		ret = qm_set_xqc_vft(qm, i, q_base, act_q_num);
		if (ret) {
			for (j = 1; j < i; j++)
				(void)qm_set_xqc_vft(qm, j, 0, 0);
			return ret;
		}
		q_base += act_q_num;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

enum hisi_drv_status hisi_qm_start(struct hisi_qm *qm)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	if (qm->fun_type == HISI_QM_HW_PF) {
		ret = qm_hw_mem_reset(qm);
		if (ret) {
			EMSG("Fail to reset QM hardware mem");
			return ret;
		}

		ret = qm_set_xqc_vft(qm, 0, qm->qp_base, qm->qp_num);
		if (ret) {
			EMSG("Fail to set PF xqc_vft");
			return ret;
		}

		ret = qm_func_vft_cfg(qm);
		if (ret) {
			EMSG("Fail to set VF xqc_vft");
			return ret;
		}
	}

	ret = hisi_qm_mb_write(qm, QM_MB_CMD_SQC_BT, qm->xqc.sqc_dma, 0);
	if (ret) {
		EMSG("Fail to set sqc_bt");
		return ret;
	}

	ret = hisi_qm_mb_write(qm, QM_MB_CMD_CQC_BT, qm->xqc.cqc_dma, 0);
	if (ret) {
		EMSG("Fail to set cqc_bt");
		return ret;
	}

	/* Security mode does not support msi */
	io_write32(qm->io_base + QM_VF_AEQ_INT_MASK, QM_VF_AEQ_INT_MASK_EN);
	io_write32(qm->io_base + QM_VF_EQ_INT_MASK, QM_VF_EQ_INT_MASK_EN);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void qm_disable_clock_gate(struct hisi_qm *qm)

{
	if (qm->version == HISI_QM_HW_V2)
		return;

	io_setbits32(qm->io_base + QM_PM_CTRL0, QM_IDLE_DISABLE);
}

void hisi_qm_dev_init(struct hisi_qm *qm)
{
	if (qm->fun_type == HISI_QM_HW_VF)
		return;

	qm_disable_clock_gate(qm);

	/* QM user domain */
	io_write32(qm->io_base + QM_ARUSER_M_CFG_1, QM_AXUSER_CFG);
	io_write32(qm->io_base + QM_ARUSER_M_CFG_ENABLE, AXUSER_M_CFG_ENABLE);
	io_write32(qm->io_base + QM_AWUSER_M_CFG_1, QM_AXUSER_CFG);
	io_write32(qm->io_base + QM_AWUSER_M_CFG_ENABLE, AXUSER_M_CFG_ENABLE);
	/* QM cache */
	io_write32(qm->io_base + QM_AXI_M_CFG, AXI_M_CFG);

	if (qm->version == HISI_QM_HW_V2) {
		/* Disable FLR triggered by BME(bus master enable) */
		io_write32(qm->io_base + QM_PEH_AXUSER_CFG, PEH_AXUSER_CFG);
		/* Set sec sqc and cqc cache wb threshold 4 */
		io_write32(qm->io_base + QM_CACHE_CTL, QM_CACHE_CFG);
	}
	/* Disable QM ras */
	io_write32(qm->io_base + HISI_QM_ABNML_INT_MASK,
		   HISI_QM_ABNML_INT_MASK_CFG);
	/* Set doorbell timeout to QM_DB_TIMEOUT_SET ns */
	io_write32(qm->io_base + QM_DB_TIMEOUT_CFG, QM_DB_TIMEOUT_SET);
}

static enum hisi_drv_status qm_sqc_cfg(struct hisi_qp *qp)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_qm *qm = qp->qm;
	struct qm_sqc *sqc = qm->cfg_xqc.sqc;
	struct qm_mailbox mb = { };

	mutex_lock(&qm->mailbox_lock);
	memset(sqc, 0, sizeof(struct qm_sqc));
	reg_pair_from_64(qp->sqe_dma, &sqc->base_h, &sqc->base_l);
	sqc->dw3 = (HISI_QM_Q_DEPTH - 1) |
		    SHIFT_U32(qm->sqe_log2_size, QM_SQ_SQE_SIZE_SHIFT);
	sqc->rand_data = QM_DB_RAND_DATA;
	sqc->cq_num = qp->qp_id;
	sqc->w13 = BIT32(QM_SQ_ORDER_SHIFT) |
		   SHIFT_U32(qp->sq_type, QM_SQ_TYPE_SHIFT);

	qm_mb_init(&mb, QM_MB_CMD_SQC, qm->cfg_xqc.sqc_dma, qp->qp_id,
		   QM_MB_OP_WR);
	ret = qm_mb_nolock(qm, &mb);
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static enum hisi_drv_status qm_cqc_cfg(struct hisi_qp *qp)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_qm *qm = qp->qm;
	struct qm_cqc *cqc = qm->cfg_xqc.cqc;
	struct qm_mailbox mb = { };

	mutex_lock(&qm->mailbox_lock);
	memset(cqc, 0, sizeof(struct qm_cqc));
	reg_pair_from_64(qp->cqe_dma, &cqc->base_h, &cqc->base_l);
	cqc->dw3 = (HISI_QM_Q_DEPTH - 1) |
		    SHIFT_U32(QM_CQE_SIZE, QM_CQ_CQE_SIZE_SHIFT);
	cqc->rand_data = QM_DB_RAND_DATA;
	cqc->dw6 = PHASE_DEFAULT_VAL;

	qm_mb_init(&mb, QM_MB_CMD_CQC, qm->cfg_xqc.cqc_dma, qp->qp_id,
		   QM_MB_OP_WR);
	ret = qm_mb_nolock(qm, &mb);
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, uint8_t sq_type)
{
	struct hisi_qp *qp = NULL;
	int cur_idx = 0;
	uint32_t i = 0;

	mutex_lock(&qm->qp_lock);
	if (qm->qp_in_used == qm->qp_num) {
		EMSG("All %"PRIu32" queues of QM are busy", qm->qp_num);
		goto err_proc;
	}

	for (i = 0; i < qm->qp_num; i++) {
		cur_idx = (qm->qp_idx + i) % qm->qp_num;
		if (!qm->qp_array[cur_idx].used) {
			qm->qp_array[cur_idx].used = true;
			qm->qp_idx = cur_idx + 1;
			break;
		}
	}

	qp = qm->qp_array + cur_idx;
	memset(qp->cqe, 0, sizeof(struct qm_cqe) * HISI_QM_Q_DEPTH);
	qp->sq_type = sq_type;
	qp->sq_tail = 0;
	qp->cq_head = 0;
	qp->cqc_phase = true;

	if (qm_sqc_cfg(qp)) {
		EMSG("Fail to set qp[%"PRIu32"] sqc", qp->qp_id);
		goto err_qp_release;
	}

	if (qm_cqc_cfg(qp)) {
		EMSG("Fail to set qp[%"PRIu32"] cqc", qp->qp_id);
		goto err_qp_release;
	}

	qm->qp_in_used++;
	mutex_unlock(&qm->qp_lock);
	return qp;

err_qp_release:
	qp->used = false;
err_proc:
	qp->sq_type = 0;
	qp->cqc_phase = false;
	mutex_unlock(&qm->qp_lock);
	return NULL;
}

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct hisi_qm *qm = NULL;

	if (!qp) {
		EMSG("QP is NULL");
		return;
	}

	qm = qp->qm;
	mutex_lock(&qm->qp_lock);
	qm->qp_in_used--;
	qp->used = false;
	mutex_unlock(&qm->qp_lock);
}

static void qm_sq_tail_update(struct hisi_qp *qp)
{
	if (qp->sq_tail == HISI_QM_Q_DEPTH - 1)
		qp->sq_tail = 0;
	else
		qp->sq_tail++;
}

/*
 * One task thread will just bind to one hardware queue, and
 * hardware does not support msi. So we have no lock here.
 */
enum hisi_drv_status hisi_qp_send(struct hisi_qp *qp, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_qm *qm = NULL;
	void *sqe = NULL;

	if (!qp) {
		EMSG("QP is NULL");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	qm = qp->qm;
	ret = qm->dev_status_check(qm);
	if (ret)
		return ret;

	sqe = (void *)((vaddr_t)qp->sqe + qm->sqe_size * qp->sq_tail);
	memset(sqe, 0, qm->sqe_size);

	ret = qp->fill_sqe(sqe, msg);
	if (ret) {
		EMSG("Fail to fill sqe");
		return ret;
	}

	qm_sq_tail_update(qp);

	dsb();
	qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_SQ, qp->sq_tail, 0);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->cq_head == HISI_QM_Q_DEPTH - 1) {
		qp->cqc_phase = !qp->cqc_phase;
		qp->cq_head = 0;
	} else {
		qp->cq_head++;
	}
}

static enum hisi_drv_status hisi_qp_recv(struct hisi_qp *qp, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	struct hisi_qm *qm = qp->qm;
	struct qm_cqe *cqe = NULL;
	void *sqe = NULL;

	ret = qm->dev_status_check(qm);
	if (ret)
		return ret;

	cqe = qp->cqe + qp->cq_head;
	if (QM_CQE_PHASE(cqe) == qp->cqc_phase) {
		dsb_osh();
		sqe = (void *)((vaddr_t)qp->sqe + qm->sqe_size * cqe->sq_head);
		ret = qp->parse_sqe(sqe, msg);
		qm_cq_head_update(qp);
		qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ, qp->cq_head, 0);
		if (ret) {
			EMSG("Fail to parse sqe");
			return ret;
		}
	} else {
		return HISI_QM_DRVCRYPT_NO_ERR;
	}

	return HISI_QM_DRVCRYPT_RECV_DONE;
}

static void qm_dfx_dump(struct hisi_qm *qm)
{
	const struct qm_dfx_registers *regs = qm_dfx_regs;
	__maybe_unused uint32_t val = 0;

	if (qm->fun_type == HISI_QM_HW_VF)
		return;

	while (regs->reg_name) {
		val = io_read32(qm->io_base + regs->reg_offset);
		EMSG("%s= 0x%" PRIx32, regs->reg_name, val);
		regs++;
	}
}

enum hisi_drv_status hisi_qp_recv_sync(struct hisi_qp *qp, void *msg)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;
	uint32_t timeout = 0;

	if (!qp || !qp->qm || !msg) {
		EMSG("Invalid qp recv sync parameters");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	timeout = timeout_init_us(QM_SINGLE_WAIT_TIME *
				  HISI_QM_RECV_SYNC_TIMEOUT);
	while (!timeout_elapsed(timeout)) {
		ret = hisi_qp_recv(qp, msg);
		if (ret) {
			if (ret != HISI_QM_DRVCRYPT_RECV_DONE) {
				EMSG("QM recv task error");
				qm_dfx_dump(qp->qm);
				return ret;
			} else {
				return HISI_QM_DRVCRYPT_NO_ERR;
			}
		}
	}

	EMSG("QM recv task timeout");
	qm_dfx_dump(qp->qm);
	return HISI_QM_DRVCRYPT_ETMOUT;
}
