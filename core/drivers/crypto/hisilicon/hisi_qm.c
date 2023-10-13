// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 HiSilicon Limited.
 * Kunpeng hardware accelerator queue management module.
 */
#include "hisi_qm.h"

#define QM_FVT_CFG_RDY_BIT	0x1
/* doorbell */
#define QM_DOORBELL_SQ_CQ_BASE	0x1000
#define QM_DB_CMD_SHIFT		12
#define QM_DB_RAND_DATA_SHIFT	16
#define QM_DB_INDEX_SHIFT	32
#define QM_DB_PRIORITY_SHIFT	48
#define QM_DB_RAND_DATA		0x5a
#define QM_DOORBELL_CMD_SQ	0
#define QM_DOORBELL_CMD_CQ	1
/* mailbox */
#define QM_MAILBOX_BASE		0x300
#define QM_MAILBOX_DATA_ADDR_L	0x304
#define QM_MAILBOX_DATA_ADDR_H	0x308
#define QM_MB_BUSY_SHIFT	13
#define QM_MB_BUSY_BIT		BIT32(QM_MB_BUSY_SHIFT)
#define QM_MB_OP_SHIFT		14
#define QM_MB_OP_WR		0
#define QM_MB_OP_RD		1

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

static enum hisi_drv_status qm_wait_mb_ready(struct hisi_qm *qm)
{
	uint32_t val = 0;

	/* return 0 mailbox ready, HISI_QM_DRVCRYPT_ETMOUT hardware timeout */
	return IO_READ32_POLL_TIMEOUT(qm->io_base + QM_MAILBOX_BASE, val,
				      !(val & QM_MB_BUSY_BIT), POLL_PERIOD,
				      POLL_TIMEOUT);
}

static void qm_mb_write(struct hisi_qm *qm, struct qm_mailbox *mb)
{
	vaddr_t dst = qm->io_base + QM_MAILBOX_BASE;

	write_64bit_pair(dst, mb->x[0], mb->x[1]);
}

static enum hisi_drv_status qm_mb(struct hisi_qm *qm, uint8_t cmd,
				  vaddr_t dma_addr, uint16_t qn, uint8_t op)
{
	struct qm_mailbox mb = { };

	mb.w0 = cmd | SHIFT_U32(op, QM_MB_OP_SHIFT) |
		BIT32(QM_MB_BUSY_SHIFT);
	mb.queue = qn;
	reg_pair_from_64(dma_addr, &mb.base_h, &mb.base_l);
	mb.token = 0;

	if (qm_wait_mb_ready(qm)) {
		EMSG("QM mailbox is busy");
		return HISI_QM_DRVCRYPT_EBUSY;
	}

	qm_mb_write(qm, &mb);

	if (qm_wait_mb_ready(qm)) {
		EMSG("QM mailbox operation timeout");
		return HISI_QM_DRVCRYPT_EBUSY;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}
