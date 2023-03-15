// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 HiSilicon Limited.
 * Kunpeng hardware accelerator queue management module.
 */
#include "hisi_qm.h"

/* doorbell */
#define QM_DOORBELL_SQ_CQ_BASE 0x1000
#define QM_DB_CMD_SHIFT 12
#define QM_DB_RAND_DATA_SHIFT 16
#define QM_DB_INDEX_SHIFT 32
#define QM_DB_PRIORITY_SHIFT 48
#define QM_DB_RAND_DATA 0x5a
#define QM_DOORBELL_CMD_SQ 0
#define QM_DOORBELL_CMD_CQ 1
/* mailbox */
#define QM_MAILBOX_BASE 0x300
#define QM_MAILBOX_DATA_ADDR_L 0x304
#define QM_MAILBOX_DATA_ADDR_H 0x308
#define QM_MB_BUSY_SHIFT 13
#define QM_MB_OP_SHIFT 14
#define QM_MB_OP_WR 0
#define QM_MB_OP_RD 1
/* XQC_VFT */
#define QM_VFT_CFG_OP_ENABLE 0x100054
#define QM_VFT_CFG_OP_WR 0x100058
#define QM_VFT_CFG_TYPE 0x10005c
#define QM_VFT_CFG_ADDRESS 0x100060
#define QM_VFT_CFG_DATA_L 0x100064
#define QM_VFT_CFG_DATA_H 0x100068
#define QM_VFT_CFG_RDY 0x10006c
#define QM_SQC_VFT 0
#define QM_CQC_VFT 1
#define QM_SQC_VFT_START_SQN_SHIFT 28
#define QM_SQC_VFT_VALID  BIT(44)
#define QM_SQC_VFT_SQ_NUM_SHIFT 45
#define QM_CQC_VFT_VALID BIT(28)
#define QM_VFT_WRITE 0
#define QM_VFT_READ 1
#define QM_SQC_VFT_BASE_MASK 0x3ff
#define QM_SQC_VFT_NUM_MASK 0x3ff
/* QM INIT */
#define QM_MEM_START_INIT 0x100040
#define QM_MEM_INIT_DONE 0x100044
#define QM_VF_AEQ_INT_MASK 0x4
#define QM_VF_EQ_INT_MASK 0xc
#define QM_ARUSER_M_CFG_1 0x100088
#define QM_ARUSER_M_CFG_ENABLE 0x100090
#define QM_AWUSER_M_CFG_1 0x100098
#define QM_AWUSER_M_CFG_ENABLE 0x1000a0
#define QM_AXUSER_CFG 0x40001070
#define AXUSER_M_CFG_ENABLE 0x7ffffc
#define QM_AXI_M_CFG 0x1000ac
#define AXI_M_CFG 0xffff
#define QM_PEH_AXUSER_CFG 0x1000cc
#define PEH_AXUSER_CFG 0x400801
#define QM_CACHE_CTL 0x100050
#define QM_CACHE_CFG 0x4893
#define QM_CACHE_WB_START 0x100204
#define QM_CACHE_WB_DONE 0x100208
/* XQC shift */
#define QM_SQ_SQE_SIZE_SHIFT 12
#define QM_SQ_ORDER_SHIFT 4
#define QM_SQ_TYPE_SHIFT 8
#define QM_CQE_SIZE 4
#define QM_CQ_CQE_SIZE_SHIFT 12
/* CQE */
#define QM_CQE_PHASE(cqe) (((cqe)->w7) & 0x1)

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
	uint16_t w0;
	uint16_t queue;
	uint32_t base_l;
	uint32_t base_h;
	uint32_t token;
};

struct qm_dfx_registers {
	const char *reg_name;
	uint32_t reg_offset;
};

static struct qm_dfx_registers qm_dfx_regs[] = {
	{"QM_ECC_1BIT_CNT           ",  0x104000},
	{"QM_ECC_MBIT_CNT           ",  0x104008},
	{"QM_DFX_MB_CNT             ",  0x104018},
	{"QM_DFX_DB_CNT             ",  0x104028},
	{"QM_DFX_SQE_CNT            ",  0x104038},
	{"QM_DFX_CQE_CNT            ",  0x104048},
	{"QM_DFX_SEND_SQE_TO_ACC_CNT",  0x104050},
	{"QM_DFX_WB_SQE_FROM_ACC_CNT",  0x104058},
	{"QM_DFX_ACC_FINISH_CNT     ",  0x104060},
	{"QM_DFX_CQE_ERR_CNT        ",  0x1040b4},
	{ NULL, 0}
};

void hisi_qm_get_version(struct hisi_qm *qm)
{
	uint32_t val;

	val = io_read32(qm->io_base + QM_REVISON_ID_BASE);
	qm->version = val & QM_REVISON_ID_MASK;
}

static void qm_db(struct hisi_qm *qm, uint16_t qn, uint8_t cmd, uint16_t index,
		  uint8_t priority)
{
	uint16_t rand_data = QM_DB_RAND_DATA;
	uint64_t doorbell;

	doorbell = (qn | ((uint64_t)cmd << QM_DB_CMD_SHIFT) |
		   ((uint64_t)rand_data << QM_DB_RAND_DATA_SHIFT) |
		   ((uint64_t)index << QM_DB_INDEX_SHIFT) |
		   ((uint64_t)priority << QM_DB_PRIORITY_SHIFT));

	io_write64(qm->io_base + QM_DOORBELL_SQ_CQ_BASE, doorbell);
}

static int32_t qm_wait_mb_ready(struct hisi_qm *qm)
{
	uint32_t val;

	/* return 0 mailbox ready, -ETIMEDOUT hardware timeout */
	return readl_relaxed_poll_timeout(qm->io_base + QM_MAILBOX_BASE,
					  val, !((val >> QM_MB_BUSY_SHIFT) &
					  0x1), POLL_PERIOD, POLL_TIMEOUT);
}

static void qm_mb_write(struct hisi_qm *qm, void *src)
{
	uintptr_t dst = qm->io_base + QM_MAILBOX_BASE;
	unsigned long tmp0 = 0, tmp1 = 0;

	/* 128bits should be written to hardware at one time */
	asm volatile ("ldp %0, %1, %3\n"
		      "stp %0, %1, %2\n"
		      "dsb sy\n"
		      : "=&r"(tmp0), "=&r"(tmp1), "+Q"(*((char *)dst))
		      : "Q"(*((char *)src))
		      : "memory");
}

static int32_t qm_mb(struct hisi_qm *qm, uint8_t cmd, uintptr_t dma_addr,
		     uint16_t qn, uint8_t op)
{
	struct qm_mailbox mb;

	mb.w0 = (cmd | (op ? 0x1 << QM_MB_OP_SHIFT : 0) |
		(0x1 << QM_MB_BUSY_SHIFT));
	mb.queue = qn;
	mb.base_l = lower_32_bits(dma_addr);
	mb.base_h = upper_32_bits(dma_addr);
	mb.token = 0;

	if (qm_wait_mb_ready(qm)) {
		EMSG("QM mailbox is busy");
		return -DRVCRYPT_EBUSY;
	}

	qm_mb_write(qm, &mb);

	if (qm_wait_mb_ready(qm)) {
		EMSG("QM mailbox operation timeout");
		return -DRVCRYPT_EBUSY;
	}

	return TEE_SUCCESS;
}

static void qm_cfg_vft_data(struct hisi_qm *qm, uint8_t vft_type,
			    uint32_t base, uint32_t number)
{
	uint64_t data = 0;

	switch (vft_type) {
	case QM_SQC_VFT:
		data = ((uint64_t)base << QM_SQC_VFT_START_SQN_SHIFT |
			QM_SQC_VFT_VALID |
			(uint64_t)(number - 1) << QM_SQC_VFT_SQ_NUM_SHIFT);
		break;
	case QM_CQC_VFT:
		data = QM_CQC_VFT_VALID;
		break;
	default:
		EMSG("Invalid vft type");
		break;
	}

	io_write32(qm->io_base + QM_VFT_CFG_DATA_L, lower_32_bits(data));
	io_write32(qm->io_base + QM_VFT_CFG_DATA_H, upper_32_bits(data));
}

static int32_t qm_set_vft_common(struct hisi_qm *qm, uint8_t vft_type,
				 uint32_t function, uint32_t base, uint32_t num)
{
	uint32_t val = 0;
	int32_t ret = 0;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & 0x1, POLL_PERIOD, POLL_TIMEOUT);
	if (ret) {
		EMSG("QM VFT is not ready");
		return ret;
	}

	io_write32(qm->io_base + QM_VFT_CFG_OP_WR, QM_VFT_WRITE);
	io_write32(qm->io_base + QM_VFT_CFG_TYPE, vft_type);
	io_write32(qm->io_base + QM_VFT_CFG_ADDRESS, function);
	qm_cfg_vft_data(qm, vft_type, base, num);
	io_write32(qm->io_base + QM_VFT_CFG_RDY, 0x0);
	io_write32(qm->io_base + QM_VFT_CFG_OP_ENABLE, 0x1);

	return readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					  val & 0x1, POLL_PERIOD, POLL_TIMEOUT);
}

static int32_t qm_set_xqc_vft(struct hisi_qm *qm, uint32_t function,
			      uint32_t base, uint32_t num)
{
	int32_t ret, i;

	if (!num) {
		EMSG("Invalid sq num");
		return -DRVCRYPT_EINVAL;
	}

	for (i = QM_SQC_VFT; i <= QM_CQC_VFT; i++) {
		ret = qm_set_vft_common(qm, i, function, base, num);
		if (ret) {
			EMSG("QM set type%d fail!\n", i);
			return ret;
		}
	}

	return TEE_SUCCESS;
}

static int32_t qm_get_vft(struct hisi_qm *qm, uint32_t *base, uint32_t *num)
{
	uint64_t sqc_vft;
	int32_t ret = 0;

	ret = qm_mb(qm, QM_MB_CMD_SQC_VFT, 0, 0, QM_MB_OP_RD);
	if (ret)
		return ret;

	sqc_vft = io_read64(qm->io_base + QM_MAILBOX_DATA_ADDR_L);
	*base = (sqc_vft >> QM_SQC_VFT_START_SQN_SHIFT) & QM_SQC_VFT_BASE_MASK;
	*num = ((sqc_vft >> QM_SQC_VFT_SQ_NUM_SHIFT) & QM_SQC_VFT_NUM_MASK) + 1;

	return TEE_SUCCESS;
}

static void hisi_qp_memory_uninit(struct hisi_qm *qm, uint32_t id)
{
	struct hisi_qp *qp = &qm->qp_array[id];

	free(qp->sqe);
	free(qp->cqe);
}

static int32_t hisi_qp_memory_init(struct hisi_qm *qm, uint32_t id)
{
	size_t sq_size = qm->sqe_size * QM_Q_DEPTH;
	size_t cq_size = sizeof(struct qm_cqe) * QM_Q_DEPTH;
	struct hisi_qp *qp = &qm->qp_array[id];
	int32_t ret = 0;

	qp->sqe = memalign(QM_ALIGN128, sq_size);
	if (!qp->sqe) {
		EMSG("Fail to malloc sq[%u]!\n", id);
		return -DRVCRYPT_ENOMEM;
	}
	qp->sqe_dma = virt_to_phys(qp->sqe);
	assert(qp->sqe_dma);
	qp->cqe = (struct qm_cqe *)memalign(QM_ALIGN32, cq_size);
	if (!qp->cqe) {
		EMSG("Fail to malloc cq[%u]!\n", id);
		ret = -DRVCRYPT_ENOMEM;
		goto free_sqe;
	}
	qp->cqe_dma = virt_to_phys(qp->cqe);
	assert(qp->cqe_dma);

	qp->qp_id = id;
	qp->qm = qm;
	return TEE_SUCCESS;

free_cqe:
	free(qp->cqe);
free_sqe:
	free(qp->sqe);
	return ret;
}

static void qm_memory_uninit(struct hisi_qm *qm)
{
	uint32_t i;

	for (i = 0; i < qm->qp_num; i++)
		hisi_qp_memory_uninit(qm, i);

	free(qm->qp_array);
	free(qm->sqc);
	free(qm->cqc);
}

static int32_t qm_memory_init(struct hisi_qm *qm)
{
	size_t sqc_size, cqc_size, qp_size;
	int32_t j, ret;
	uint32_t i;

	sqc_size = sizeof(struct qm_sqc) * qm->qp_num;
	cqc_size = sizeof(struct qm_cqc) * qm->qp_num;
	qp_size = sizeof(struct hisi_qp) * qm->qp_num;

	qm->sqc = (struct qm_sqc *)memalign(QM_ALIGN32, sqc_size);
	if (!qm->sqc) {
		EMSG("Fail to malloc sqc");
		return -DRVCRYPT_ENOMEM;
	}
	qm->sqc_dma = virt_to_phys(qm->sqc);
	assert(qm->sqc_dma);
	qm->cqc = (struct qm_cqc *)memalign(QM_ALIGN32, cqc_size);
	if (!qm->cqc) {
		EMSG("Fail to malloc cqc");
		ret = -DRVCRYPT_ENOMEM;
		goto free_sqc;
	}
	qm->cqc_dma = virt_to_phys(qm->cqc);
	assert(qm->cqc_dma);

	qm->qp_array = (struct hisi_qp *)malloc(qp_size);
	if (!qm->qp_array) {
		EMSG("Fail to malloc qp_array");
		ret = -DRVCRYPT_ENOMEM;
		goto free_cqc;
	}

	for (i = 0; i < qm->qp_num; i++) {
		ret = hisi_qp_memory_init(qm, i);
		if (ret) {
			ret = -DRVCRYPT_ENOMEM;
			goto free_qp_mem;
		}
	}

	return TEE_SUCCESS;

free_qp_mem:
	for (j = (int32_t)i - 1; j >= 0; j--)
		hisi_qp_memory_uninit(qm, j);
	free(qm->qp_array);
free_cqc:
	free(qm->cqc);
free_sqc:
	free(qm->sqc);
	return ret;
}

int32_t hisi_qm_init(struct hisi_qm *qm)
{
	int32_t ret = 0;

	if (qm->fun_type == QM_HW_VF) {
		ret = qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
		if (ret) {
			EMSG("Fail to get function vft config");
			return ret;
		}
	}

	if (qm->qp_num == 0 || qm->sqe_size == 0) {
		EMSG("Invalid qm parameters");
		return -DRVCRYPT_EINVAL;
	}

	ret = qm_memory_init(qm);
	if (ret)
		return ret;

	qm->qp_in_used = 0;
	qm->qp_idx = 0;
	mutex_init(&qm->qp_lock);

	return TEE_SUCCESS;
}

static void qm_cache_writeback(struct hisi_qm *qm)
{
	uint32_t val = 0;

	io_write32(qm->io_base + QM_CACHE_WB_START, 0x1);

	if (readl_relaxed_poll_timeout(qm->io_base + QM_CACHE_WB_DONE, val,
				       val & 0x1, POLL_PERIOD, POLL_TIMEOUT))
		EMSG("QM writeback sqc cache fail");
}

void hisi_qm_uninit(struct hisi_qm *qm)
{
	qm_cache_writeback(qm);
	qm_memory_uninit(qm);
	mutex_destroy(&qm->qp_lock);
}

static int32_t qm_hw_mem_reset(struct hisi_qm *qm)
{
	uint32_t val;

	io_write32(qm->io_base + QM_MEM_START_INIT, 0x1);

	return readl_relaxed_poll_timeout(qm->io_base + QM_MEM_INIT_DONE, val,
					  val & 0x1, POLL_PERIOD,
					  POLL_TIMEOUT);
}

static int32_t qm_func_vft_cfg(struct hisi_qm *qm)
{
	uint32_t q_base = qm->qp_num;
	uint32_t act_q_num = 0;
	uint32_t i = 0;
	uint32_t j = 0;
	int32_t ret = 0;

	if (qm->vfs_num == 0)
		return TEE_SUCCESS;

	if (qm->vfs_num > QM_MAX_VFS_NUM) {
		EMSG("Invalid QM vfs_num");
		return -DRVCRYPT_EINVAL;
	}

	for (i = 1; i <= qm->vfs_num; i++) {
		act_q_num = QM_VF_Q_NUM;
		ret = qm_set_xqc_vft(qm, i, q_base, act_q_num);
		if (ret) {
			for (j = 1; j < i; j++)
				(void)qm_set_xqc_vft(qm, j, 0, 0);
			return ret;
		}
		q_base += act_q_num;
	}

	return TEE_SUCCESS;
}

int32_t hisi_qm_start(struct hisi_qm *qm)
{
	int32_t ret = 0;

	if (qm->fun_type == QM_HW_PF) {
		ret = qm_hw_mem_reset(qm);
		if (ret) {
			EMSG("Fail to reset qm hardware mem");
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

	ret = qm_mb(qm, QM_MB_CMD_SQC_BT, qm->sqc_dma, 0, QM_MB_OP_WR);
	if (ret) {
		EMSG("Fail to set sqc_bt");
		return ret;
	}

	ret = qm_mb(qm, QM_MB_CMD_CQC_BT, qm->cqc_dma, 0, QM_MB_OP_WR);
	if (ret) {
		EMSG("Fail to set cqc_bt");
		return ret;
	}

	/* security mode does not support msi */
	io_write32(qm->io_base + QM_VF_AEQ_INT_MASK, 0x1);
	io_write32(qm->io_base + QM_VF_EQ_INT_MASK, 0x1);

	return TEE_SUCCESS;
}

void hisi_qm_dev_init(struct hisi_qm *qm)
{
	if (qm->fun_type == QM_HW_VF)
		return;

	/* qm user domain */
	io_write32(qm->io_base + QM_ARUSER_M_CFG_1, QM_AXUSER_CFG);
	io_write32(qm->io_base + QM_ARUSER_M_CFG_ENABLE, AXUSER_M_CFG_ENABLE);
	io_write32(qm->io_base + QM_AWUSER_M_CFG_1, QM_AXUSER_CFG);
	io_write32(qm->io_base + QM_AWUSER_M_CFG_ENABLE, AXUSER_M_CFG_ENABLE);
	/* qm cache */
	io_write32(qm->io_base + QM_AXI_M_CFG, AXI_M_CFG);

	if (qm->version == QM_HW_V2) {
		/* disable FLR triggered by BME(bus master enable) */
		io_write32(qm->io_base + QM_PEH_AXUSER_CFG, PEH_AXUSER_CFG);
		/* set sec sqc and cqc cache wb threshold 4 */
		io_write32(qm->io_base + QM_CACHE_CTL, QM_CACHE_CFG);
	}
	/* disable qm ras */
	io_write32(qm->io_base + QM_ABNML_INT_MASK, QM_ABNML_INT_MASK_CFG);
}

static int32_t qm_sqc_cfg(struct hisi_qp *qp)
{
	struct hisi_qm *qm = qp->qm;
	struct qm_sqc *sqc;
	paddr_t sqc_dma;
	int ret;

	sqc = (struct qm_sqc *)memalign(QM_ALIGN32, sizeof(struct qm_sqc));
	if (!sqc)
		return -DRVCRYPT_ENOMEM;

	sqc_dma = virt_to_phys(sqc);
	assert(sqc_dma);

	memset(sqc, 0, sizeof(struct qm_sqc));
	sqc->base_l = lower_32_bits(qp->sqe_dma);
	sqc->base_h = upper_32_bits(qp->sqe_dma);
	sqc->dw3 = (QM_Q_DEPTH - 1) | qm->sqe_log2_size << QM_SQ_SQE_SIZE_SHIFT;
	sqc->rand_data = QM_DB_RAND_DATA;
	sqc->cq_num = qp->qp_id;
	sqc->w13 = 0x1 << QM_SQ_ORDER_SHIFT |
		   (uint16_t)qp->sq_type << QM_SQ_TYPE_SHIFT;

	ret = qm_mb(qm, QM_MB_CMD_SQC, sqc_dma, qp->qp_id, QM_MB_OP_WR);
	free(sqc);

	return ret;
}

static int32_t qm_cqc_cfg(struct hisi_qp *qp)
{
	struct hisi_qm *qm = qp->qm;
	struct qm_cqc *cqc;
	paddr_t cqc_dma;
	int ret;

	cqc = (struct qm_cqc *)memalign(QM_ALIGN32, sizeof(struct qm_cqc));
	if (!cqc)
		return -DRVCRYPT_ENOMEM;

	cqc_dma = virt_to_phys(cqc);
	assert(cqc_dma);

	memset(cqc, 0, sizeof(struct qm_cqc));
	cqc->base_l = lower_32_bits(qp->cqe_dma);
	cqc->base_h = upper_32_bits(qp->cqe_dma);
	cqc->dw3 = (QM_Q_DEPTH - 1) | QM_CQE_SIZE << QM_CQ_CQE_SIZE_SHIFT;
	cqc->rand_data = QM_DB_RAND_DATA;
	cqc->dw6 = 0x1;

	ret = qm_mb(qm, QM_MB_CMD_CQC, cqc_dma, qp->qp_id, QM_MB_OP_WR);
	free(cqc);

	return ret;
}

struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, uint8_t sq_type)
{
	struct hisi_qp *qp;

	mutex_lock(&qm->qp_lock);
	if (qm->qp_in_used == qm->qp_num) {
		EMSG("All %u queues of QM are busy!\n", qm->qp_num);
		goto err_proc;
	}

	if (qm->qp_idx == qm->qp_num - 1)
		qm->qp_idx = 0;
	else
		qm->qp_idx++;

	qp = &qm->qp_array[qm->qp_idx];
	memset(qp->cqe, 0, sizeof(struct qm_cqe) * QM_Q_DEPTH);
	qp->sq_type = sq_type;
	qp->sq_tail = 0;
	qp->cq_head = 0;
	qp->cqc_phase = true;

	if (qm_sqc_cfg(qp)) {
		EMSG("Fail to set qp[%u] sqc!\n", qp->qp_id);
		goto err_proc;
	}

	if (qm_cqc_cfg(qp)) {
		EMSG("Fail to set qp[%u] cqc!\n", qp->qp_id);
		goto err_proc;
	}

	qm->qp_in_used++;
	mutex_unlock(&qm->qp_lock);
	return qp;

err_proc:
	mutex_unlock(&qm->qp_lock);
	return NULL;
}

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct hisi_qm *qm;

	if (!qp) {
		EMSG("qp is NULL");
		return;
	}

	qm = qp->qm;
	mutex_lock(&qm->qp_lock);
	qm->qp_in_used--;
	mutex_unlock(&qm->qp_lock);
}

static void qm_sq_tail_update(struct hisi_qp *qp)
{
	if (qp->sq_tail == QM_Q_DEPTH - 1)
		qp->sq_tail = 0;
	else
		qp->sq_tail++;
}

/*
 * One task thread will just bind to one hardware queue, and
 * hardware does not support msi. So we have no lock here.
 */
int32_t hisi_qp_send(struct hisi_qp *qp, void *msg)
{
	struct hisi_qm *qm = NULL;
	uintptr_t tmp = 0;
	int32_t ret = 0;
	void *sqe = NULL;

	if (!qp) {
		EMSG("qp is NULL");
		return -DRVCRYPT_EINVAL;
	}

	qm = qp->qm;
	ret = qm->dev_status_check(qm);
	if (ret)
		return ret;

	tmp = (uintptr_t)qp->sqe + qm->sqe_size * qp->sq_tail;
	sqe = (void *)tmp;
	memset(sqe, 0, qm->sqe_size);

	ret = qp->fill_sqe(sqe, msg);
	if (ret) {
		EMSG("Fail to fill sqe");
		return ret;
	}

	qm_sq_tail_update(qp);

	__asm__ volatile("dsb sy");
	qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_SQ, qp->sq_tail, 0);

	return TEE_SUCCESS;
}

static void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->cq_head == QM_Q_DEPTH - 1) {
		qp->cqc_phase = !qp->cqc_phase;
		qp->cq_head = 0;
	} else {
		qp->cq_head++;
	}
}

static int32_t hisi_qp_recv(struct hisi_qp *qp, void *msg)
{
	struct hisi_qm *qm = qp->qm;
	struct qm_cqe *cqe;
	uintptr_t tmp;
	int32_t ret = 0;
	void *sqe;

	ret = qm->dev_status_check(qm);
	if (ret)
		return ret;

	cqe = qp->cqe + qp->cq_head;
	if (QM_CQE_PHASE(cqe) == qp->cqc_phase) {
		__asm__ volatile("dmb osh");
		tmp = (uintptr_t)qp->sqe + qm->sqe_size * cqe->sq_head;
		sqe = (void *)tmp;
		ret = qp->parse_sqe(sqe, msg);
		qm_cq_head_update(qp);
		qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ, qp->cq_head, 0);
		if (ret) {
			EMSG("Fail to parse sqe");
			return ret;
		}
	} else {
		return TEE_SUCCESS;
	}

	return 1;
}

static void qm_dfx_dump(struct hisi_qm *qm)
{
	struct qm_dfx_registers *regs;
	uint32_t val;

	if (qm->fun_type == QM_HW_VF)
		return;

	regs = qm_dfx_regs;
	while (regs->reg_name) {
		val = io_read32(qm->io_base + regs->reg_offset);
		EMSG("%s= 0x%x\n", regs->reg_name, val);
		regs++;
	}
}

int32_t hisi_qp_recv_sync(struct hisi_qp *qp, void *msg)
{
	uint32_t cnt = 0;
	int32_t ret = 0;

	if (!qp) {
		EMSG("qp is NULL");
		return -DRVCRYPT_EINVAL;
	}

	while (true) {
		ret = hisi_qp_recv(qp, msg);
		if (ret == 0) {
			if (++cnt > QM_RECV_SYNC_TIMEOUT) {
				EMSG("qm recv task timeout");
				qm_dfx_dump(qp->qm);
				ret = -DRVCRYPT_ETMOUT;
				break;
			}
		} else if (ret < 0) {
			EMSG("qm recv task error");
			qm_dfx_dump(qp->qm);
			break;
		} else if (ret > 0) {
			return TEE_SUCCESS;
		}
	}

	return ret;
}
