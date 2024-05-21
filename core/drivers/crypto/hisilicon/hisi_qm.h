/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2023, Huawei Technologies Co., Ltd
 */
#ifndef __HISI_QM_H__
#define __HISI_QM_H__

#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>

#define HISI_QM_HW_V2 0x21
#define HISI_QM_HW_V3 0x30
#define HISI_QM_MAX_VFS_NUM 63
#define HISI_QM_PF_Q_BASE 0
#define HISI_QM_PF_Q_NUM 64
#define HISI_QM_VF_Q_NUM 15
#define HISI_QM_Q_DEPTH 8
#define PHASE_DEFAULT_VAL 0x1

#define HISI_QM_ABNML_INT_MASK 0x100004
#define HISI_QM_ABNML_INT_MASK_CFG 0x7fff
#define HISI_QM_ABNML_INT_SRC 0x100000
#define HISI_QM_HPRE_NFE_INT_MASK 0x6fb7
#define HISI_QM_SEC_NFE_INT_MASK 0x6ff7
#define HISI_QM_INVALID_DB BIT(12)
#define HISI_QM_REVISON_ID_BASE 0x1000dc
#define HISI_QM_REVISON_ID_MASK GENMASK_32(7, 0)
#define POLL_PERIOD 10
#define POLL_TIMEOUT 1000
#define HISI_QM_RECV_SYNC_TIMEOUT 0xfffff
#define HISI_QM_ALIGN128 128
#define HISI_QM_ALIGN32 32
#define QM_SINGLE_WAIT_TIME 5
#define ADDR_U64(upper, lower) ((uint64_t)(upper) << 32 | (lower))

enum qm_fun_type {
	HISI_QM_HW_PF,
	HISI_QM_HW_VF,
};

enum qm_sq_type {
	HISI_QM_CHANNEL_TYPE0 = 0,
	HISI_QM_CHANNEL_TYPE1,
	HISI_QM_CHANNEL_TYPE2,
};

struct qm_sqc {
	uint16_t head;
	uint16_t tail;
	uint32_t base_l;
	uint32_t base_h;
	/*
	 * qes : 12
	 * sqe : 4
	 * rsv(stash_nid/stash_en) : 16
	 */
	uint32_t dw3;
	uint16_t rand_data;
	uint16_t rsv0;
	uint16_t pasid;
	/*
	 * rsv : 5
	 * head_sig : 1
	 * tail_sig : 1
	 * pasid_en : 1
	 * rsv : 8
	 */
	uint16_t w11;
	uint16_t cq_num;
	/*
	 * priority(Credit): 4
	 * order(order/fc/close/rsv) : 4
	 * type : 4
	 * rsv : 4
	 */
	uint16_t w13;
	uint32_t rsv1;
};

struct qm_cqc {
	uint16_t head;
	uint16_t tail;
	uint32_t base_l;
	uint32_t base_h;
	/*
	 * qes : 12
	 * cqe_size : 4
	 * rsv(stash_nid/stash_en) : 16
	 */
	uint32_t dw3;
	uint16_t rand_data;
	uint16_t rsv0;
	uint16_t pasid;
	/*
	 * pasid_en : 1
	 * rsv : 4
	 * head_sig : 1
	 * tail_sig : 1
	 * rsv : 9
	 */
	uint16_t w11;
	/*
	 * phase : 1
	 * c_flag : 1
	 * stash_vld : 1
	 */
	uint32_t dw6;
	uint32_t rsv1;
};

struct qm_cqe {
	uint32_t rsv0;
	uint16_t cmd_id;
	uint16_t rsv1;
	uint16_t sq_head;
	uint16_t sq_id;
	uint16_t rsv2;
	/*
	 * p : 1
	 * status : 15
	 */
	uint16_t w7;
};

struct hisi_qp {
	struct hisi_qm *qm;
	uint32_t qp_id;
	uint8_t sq_type;
	uint16_t sq_tail;
	uint16_t cq_head;
	bool cqc_phase;
	bool used;

	void *sqe;
	struct qm_cqe *cqe;
	paddr_t sqe_dma;
	paddr_t cqe_dma;

	enum hisi_drv_status (*fill_sqe)(void *sqe, void *msg);
	enum hisi_drv_status (*parse_sqe)(void *sqe, void *msg);
};

struct qm_xqc {
	struct qm_sqc *sqc;
	struct qm_cqc *cqc;
	paddr_t sqc_dma;
	paddr_t cqc_dma;
};

struct hisi_qm {
	enum qm_fun_type fun_type;
	vaddr_t io_base;
	uint32_t io_size;
	uint32_t vfs_num;
	uint32_t version;

	struct qm_xqc xqc;
	struct qm_xqc cfg_xqc;
	uint32_t sqe_size;
	uint32_t sqe_log2_size;
	uint32_t qp_base;
	uint32_t qp_num;
	uint32_t qp_in_used;
	uint32_t qp_idx;
	struct hisi_qp *qp_array;
	struct mutex qp_lock; /* protect the qp instance */
	struct mutex mailbox_lock;

	enum hisi_drv_status (*dev_status_check)(struct hisi_qm *qm);
};

enum hisi_drv_status {
	HISI_QM_DRVCRYPT_NO_ERR = 0,
	HISI_QM_DRVCRYPT_FAIL = 1,
	HISI_QM_DRVCRYPT_EIO = 5,
	HISI_QM_DRVCRYPT_EAGAIN = 11,
	HISI_QM_DRVCRYPT_ENOMEM = 12,
	HISI_QM_DRVCRYPT_EFAULT = 14,
	HISI_QM_DRVCRYPT_EBUSY = 16,
	HISI_QM_DRVCRYPT_ENODEV = 19,
	HISI_QM_DRVCRYPT_EINVAL = 22,
	HISI_QM_DRVCRYPT_ETMOUT = 110,
	HISI_QM_DRVCRYPT_RECV_DONE = 175,
	HISI_QM_DRVCRYPT_ENOPROC,
	HISI_QM_DRVCRYPT_IN_EPARA,
	HISI_QM_DRVCRYPT_VERIFY_ERR,
	HISI_QM_DRVCRYPT_HW_EACCESS,
};

struct acc_device {
	struct hisi_qm qm;
	vaddr_t io_base;
	uint32_t io_size;
	uint32_t vfs_num;
	uint32_t endian;
	enum qm_fun_type fun_type;
	SLIST_ENTRY(acc_device) link;
};

/**
 * @Description: Get the version information of QM hardware
 * @param qm: Handle of Queue Management module
 */
void hisi_qm_get_version(struct hisi_qm *qm);

/**
 * @Description: Init QM for Kunpeng drv
 * @param qm: Handle of Queue Management module
 * @return success: HISI_QM_DRVCRYPT_NO_ERR，
 * fail: HISI_QM_DRVCRYPT_EBUSY/HISI_QM_DRVCRYPT_EINVAL
 */
enum hisi_drv_status hisi_qm_init(struct hisi_qm *qm);

/**
 * @Description:deinit QM for Kunpeng drv
 * @param qm: Handle of Queue Management module
 */
void hisi_qm_uninit(struct hisi_qm *qm);

/**
 * @Description: Start QM for Kunpeng drv
 * @param qm: Handle of Queue Management module
 */
enum hisi_drv_status hisi_qm_start(struct hisi_qm *qm);

/**
 * @Description: Config QM for Kunpeng drv
 * @param qm: Handle of Queue Management module
 */
void hisi_qm_dev_init(struct hisi_qm *qm);

/**
 * @Description: Create Queue Pair, allocated to PF/VF for configure
 * and service use. Each QP includes one SQ and one CQ
 * @param qm: Handle of Queue Management module
 * @param sq_type: Accelerator specific algorithm type in sqc
 * @return success: Handle of QP，fail: NULL
 */
struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, uint8_t sq_type);

/**
 * @Description:Release Queue Pair
 * @param qp: Handle of Queue Pair
 */
void hisi_qm_release_qp(struct hisi_qp *qp);

/**
 * @Description: Send SQE(Submmision Queue Element) to Kunpeng dev
 * @param qp: Handle of Queue Pair
 * @param msg: The message
 * @return success: HISI_QM_DRVCRYPT_NO_ERR，fail: HISI_QM_DRVCRYPT_EINVAL
 */
enum hisi_drv_status hisi_qp_send(struct hisi_qp *qp, void *msg);

/**
 * @Description: Recevice result from Kunpeng dev
 * @param qp: Handle of Queue Pair
 * @param msg: The message
 * @return success: HISI_QM_DRVCRYPT_NO_ERR
 * fail: HISI_QM_DRVCRYPT_EINVAL/ETMOUT
 */
enum hisi_drv_status hisi_qp_recv_sync(struct hisi_qp *qp, void *msg);

#endif
