// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2024 HiSilicon Limited.
 * Kunpeng hardware accelerator HPRE module init.
 */

#include <hpre_main.h>
#include <initcall.h>

/* base config */
#define HPRE_COMMON_CNT_CLR_CE		0x301000
#define HPRE_CFG_AXCACHE		0x301010
#define HPRE_RDCHN_INI_CFG		0x301014
#define HPRE_BD_ENDIAN			0x301020
#define HPRE_ECC_BYPASS			0x301024
#define HPRE_POISON_BYPASS		0x30102c
#define HPRE_BD_ARUSR_CFG		0x301030
#define HPRE_BD_AWUSR_CFG		0x301034
#define HPRE_TYPES_ENB			0x301038
#define HPRE_DATA_RUSER_CFG		0x30103c
#define HPRE_DATA_WUSER_CFG		0x301040
#define HPRE_HAC_INT_MASK		0x301400
#define HPRE_RAS_ECC_1BIT_TH		0x30140c
#define HPRE_RAS_CE_ENB			0x301410
#define HPRE_RAS_NFE_ENB		0x301414
#define HPRE_RAS_FE_ENB			0x301418
#define HPRE_HAC_INT_SRC		0x301600
#define HPRE_RDCHN_INI_ST		0x301a00
#define HPRE_OOO_SHUTDOWN_SEL		0x301a3c
#define HPRE_CORE_ENB			0x302004
#define HPRE_CORE_INI_CFG		0x302020
#define HPRE_CORE_INI_STATUS		0x302080
/* clock gate */
#define HPRE_CLKGATE_CTL		0x301a10
#define HPRE_PEH_CFG_AUTO_GATE		0x301a2c
#define HPRE_CLUSTER_DYN_CTL		0x302010
#define HPRE_CORE_SHB_CFG		0x302088
#define HPRE_CORE_GATE_ENABLE		GENMASK_32(31, 30)

#define HPRE_AXCACHE_MASK		0xff
#define HPRE_HAC_INT_DISABLE		0x1ffffff
#define HPRE_RAS_CE_MASK		0x1
#define HPRE_RAS_NFE_MASK		0x1fffffe
#define HPRE_RAS_FE_MASK		0
#define HPRE_BD_LITTLE_ENDIAN		0
#define HPRE_RSA_ENB			BIT(0)
#define HPRE_ECC_ENB			BIT(1)
#define HPRE_BD_ARUSR_MASK		0x2
#define HPRE_BD_AWUSR_MASK		0x102
#define HPRE_DATA_USR_MASK		0x32
#define HPRE_CLUSTER_CORE_MASK		GENMASK_32(9, 0)

static SLIST_HEAD(, acc_device) hpre_list = SLIST_HEAD_INITIALIZER(hpre_list);

struct hisi_qp *hpre_create_qp(uint8_t sq_type)
{
	struct acc_device *hpre_dev = NULL;
	struct acc_device *cur_dev = NULL;
	struct hisi_qm *qm = NULL;
	uint32_t free_qp_num = 0;
	uint32_t max_qp_num = 0;

	/* Find the HPRE device with the most remaining qp numbers */
	SLIST_FOREACH(cur_dev, &hpre_list, link) {
		qm = &cur_dev->qm;
		if (qm->fun_type == HISI_QM_HW_PF)
			free_qp_num = HISI_QM_PF_Q_NUM - qm->qp_in_used;
		else
			free_qp_num = HISI_QM_VF_Q_NUM - qm->qp_in_used;
		if (free_qp_num > max_qp_num) {
			max_qp_num = free_qp_num;
			hpre_dev = cur_dev;
		}
	}

	if (!hpre_dev) {
		EMSG("No available hpre device");
		return NULL;
	}

	return hisi_qm_create_qp(&hpre_dev->qm, sq_type);
}

enum hisi_drv_status hpre_bin_from_crypto_bin(uint8_t *dst, const uint8_t *src,
					      uint32_t bsize, uint32_t dsize)
{
	if (!src || !dst || !dsize || !bsize) {
		EMSG("parameter error");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	if (bsize < dsize) {
		EMSG("dsize is too long");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	if (src == dst && bsize == dsize)
		return HISI_QM_DRVCRYPT_NO_ERR;

	/*
	 * Copying non-zero data and padding with zeroes in high-bits
	 * (eg: 1 2 3 0 0 -> 0 0 1 2 3)
	 */
	memmove(dst + bsize - dsize, src, dsize);
	memset(dst, 0, bsize - dsize);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

enum hisi_drv_status hpre_bin_to_crypto_bin(uint8_t *dst, const uint8_t *src,
					    uint32_t bsize, uint32_t dsize)
{
	if (!dst || !src || !bsize || !dsize) {
		EMSG("parameter error");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	if (bsize < dsize) {
		EMSG("dsize is too long");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	if (src == dst && bsize == dsize)
		return HISI_QM_DRVCRYPT_NO_ERR;
	/*
	 * Copying non-zero data and padding with zeroes in low-bits
	 * (eg: 0 0 1 2 3 -> 1 2 3 0 0)
	 */
	memmove(dst, src + bsize - dsize, dsize);
	memset(dst + dsize, 0, bsize - dsize);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status hpre_set_cluster(struct hisi_qm *qm)
{
	uint32_t val = 0;

	io_write32(qm->io_base + HPRE_CORE_ENB, HPRE_CLUSTER_CORE_MASK);
	io_write32(qm->io_base + HPRE_CORE_INI_CFG, 0x1);

	if (IO_READ32_POLL_TIMEOUT(qm->io_base + HPRE_CORE_INI_STATUS, val,
				   (val & HPRE_CLUSTER_CORE_MASK) ==
				   HPRE_CLUSTER_CORE_MASK, POLL_PERIOD,
				   POLL_TIMEOUT))
		return HISI_QM_DRVCRYPT_EBUSY;
	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_disable_clock_gate(struct hisi_qm *qm)
{
	io_write32(qm->io_base + HPRE_CLKGATE_CTL, 0x0);
	io_write32(qm->io_base + HPRE_PEH_CFG_AUTO_GATE, 0x0);
	io_write32(qm->io_base + HPRE_CLUSTER_DYN_CTL, 0x0);
	io_clrbits32(qm->io_base + HPRE_CORE_SHB_CFG, HPRE_CORE_GATE_ENABLE);
}

static void hpre_enable_clock_gate(struct hisi_qm *qm)
{
	io_write32(qm->io_base + HPRE_CLKGATE_CTL, 0x1);
	io_write32(qm->io_base + HPRE_PEH_CFG_AUTO_GATE, 0x1);
	io_write32(qm->io_base + HPRE_CLUSTER_DYN_CTL, 0x1);
	io_setbits32(qm->io_base + HPRE_CORE_SHB_CFG, HPRE_CORE_GATE_ENABLE);
}

static TEE_Result hpre_engine_init(struct acc_device *hpre_dev)
{
	struct hisi_qm *qm = &hpre_dev->qm;
	uint32_t val = 0;
	int32_t ret = 0;

	if (qm->fun_type == HISI_QM_HW_VF)
		return TEE_SUCCESS;

	hpre_disable_clock_gate(qm);
	hisi_qm_dev_init(qm);

	io_write32(qm->io_base + HPRE_CFG_AXCACHE, HPRE_AXCACHE_MASK);
	io_write32(qm->io_base + HPRE_BD_ENDIAN, HPRE_BD_LITTLE_ENDIAN);
	io_write32(qm->io_base + HPRE_RAS_CE_ENB, HPRE_RAS_CE_MASK);
	io_write32(qm->io_base + HPRE_RAS_NFE_ENB, HPRE_RAS_NFE_MASK);
	io_write32(qm->io_base + HPRE_RAS_FE_ENB, HPRE_RAS_FE_MASK);
	io_write32(qm->io_base + HPRE_HAC_INT_MASK, HPRE_HAC_INT_DISABLE);
	io_write32(qm->io_base + HPRE_POISON_BYPASS, 0x0);
	io_write32(qm->io_base + HPRE_COMMON_CNT_CLR_CE, 0x0);
	io_write32(qm->io_base + HPRE_ECC_BYPASS, 0x0);
	/* cmd_type is controlled by hac subctrl */
	io_write32(qm->io_base + HPRE_BD_ARUSR_CFG, HPRE_BD_ARUSR_MASK);
	io_write32(qm->io_base + HPRE_BD_AWUSR_CFG, HPRE_BD_AWUSR_MASK);
	io_write32(qm->io_base + HPRE_DATA_RUSER_CFG, HPRE_DATA_USR_MASK);
	io_write32(qm->io_base + HPRE_DATA_WUSER_CFG, HPRE_DATA_USR_MASK);
	io_write32(qm->io_base + HPRE_TYPES_ENB, HPRE_RSA_ENB | HPRE_ECC_ENB);
	io_write32(qm->io_base + HPRE_RDCHN_INI_CFG, 0x1);
	ret = IO_READ32_POLL_TIMEOUT(qm->io_base + HPRE_RDCHN_INI_ST, val,
				     val & 0x1, POLL_PERIOD, POLL_TIMEOUT);
	if (ret) {
		EMSG("Fail to init rd channel");
		return TEE_ERROR_BUSY;
	}

	ret = hpre_set_cluster(qm);
	if (ret) {
		EMSG("Fail to init hpre cluster cores");
		return TEE_ERROR_BUSY;
	}

	hpre_enable_clock_gate(qm);

	return TEE_SUCCESS;
}

static enum hisi_drv_status hpre_dev_status_check(struct hisi_qm *qm)
{
	uint32_t val = 0;

	val = io_read32(qm->io_base + HPRE_HAC_INT_SRC);
	if (val & HPRE_RAS_NFE_MASK) {
		EMSG("HPRE NFE RAS happened, need to reset");
		return HISI_QM_DRVCRYPT_HW_EACCESS;
	}

	val = io_read32(qm->io_base + HISI_QM_ABNML_INT_SRC);
	if (val) {
		if (val & HISI_QM_HPRE_NFE_INT_MASK)
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

static enum hisi_drv_status hpre_qm_init(struct acc_device *hpre_dev)
{
	struct hisi_qm *qm = &hpre_dev->qm;

	if (cpu_mmu_enabled()) {
		qm->io_base = (uintptr_t)phys_to_virt_io(hpre_dev->io_base,
							 hpre_dev->io_size);
		if (!qm->io_base) {
			EMSG("Fail to get qm io_base");
			return HISI_QM_DRVCRYPT_EFAULT;
		}
	} else {
		qm->io_base = hpre_dev->io_base;
	}

	qm->vfs_num = hpre_dev->vfs_num;
	qm->fun_type = hpre_dev->fun_type;
	qm->sqe_size = HPRE_SQE_SIZE;
	qm->sqe_log2_size = HPRE_SQE_LOG2_SIZE;
	if (qm->fun_type == HISI_QM_HW_PF) {
		hisi_qm_get_version(qm);
		DMSG("HPRE hardware version is 0x%"PRIx32, qm->version);
		qm->qp_base = HISI_QM_PF_Q_BASE;
		qm->qp_num = HISI_QM_PF_Q_NUM;
		qm->dev_status_check = hpre_dev_status_check;
	}

	return hisi_qm_init(qm);
}

static struct acc_device *hpre_pre_init(void)
{
	struct acc_device *hpre_dev = NULL;

	hpre_dev = calloc(1, sizeof(*hpre_dev));
	if (!hpre_dev) {
		EMSG("Fail to alloc hpre_dev");
		return NULL;
	}

	hpre_dev->io_base = HPRE_BAR_BASE;
	hpre_dev->io_size = HPRE_BAR_SIZE;
	hpre_dev->fun_type = HISI_QM_HW_PF;
	SLIST_INSERT_HEAD(&hpre_list, hpre_dev, link);

	return hpre_dev;
}

static TEE_Result hpre_probe(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct acc_device *hpre_dev = NULL;
	struct hisi_qm *qm = NULL;

	DMSG("HPRE driver init start");
	hpre_dev = hpre_pre_init();
	if (!hpre_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	qm = &hpre_dev->qm;
	if (hpre_qm_init(hpre_dev)) {
		EMSG("Fail to init hpre qm");
		goto err_with_pre_init;
	}

	ret = hpre_engine_init(hpre_dev);
	if (ret) {
		EMSG("Fail to init engine");
		goto err_with_qm_init;
	}

	if (hisi_qm_start(qm)) {
		EMSG("Fail to start qm");
		ret = TEE_ERROR_BAD_STATE;
		goto err_with_qm_init;
	}

	DMSG("HPRE driver init done");
	return TEE_SUCCESS;

err_with_qm_init:
	hisi_qm_uninit(qm);
err_with_pre_init:
	SLIST_REMOVE_HEAD(&hpre_list, link);
	free(hpre_dev);

	return ret;
}

driver_init(hpre_probe);
