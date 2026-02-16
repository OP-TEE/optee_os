/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_H_
#define _PAS_H_

#include <kernel/thread_arch.h>
#include <mm/core_memprot.h>
#include <drivers/clk_qcom.h>
#include <stdint.h>

#define DEFINE_RESOURCE_TABLE(prefix, num_res)			\
	enum {							\
		prefix##_NUM_MEM_RESOURCES = (num_res),		\
		prefix##_SIZE_MEM_RES =				\
			(sizeof(struct fw_rsc_hdr) +		\
			 sizeof(struct fw_rsc_devmem)),		\
		prefix##_RESOURCE_TABLE_HEADER_SIZE =		\
			(sizeof(struct resource_table) +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  sizeof(uint32_t))),			\
		prefix##_RESOURCE_TABLE_SIZE =			\
			(prefix##_RESOURCE_TABLE_HEADER_SIZE +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  prefix##_SIZE_MEM_RES)),		\
	}

struct resource_table {
	uint32_t ver;
	uint32_t num;
	uint32_t reserved[2];
	uint32_t offset[];
} __packed;

struct fw_rsc_hdr {
	uint32_t type;
	uint8_t data[];
} __packed;

enum fw_resource_type {
	RSC_CARVEOUT		= 0,
	RSC_DEVMEM		= 1,
	RSC_TRACE		= 2,
	RSC_VDEV		= 3,
	RSC_LAST		= 4,
	RSC_VENDOR_START	= 128,
	RSC_VENDOR_END		= 512,
};

#define IOMMU_READ	BIT(0)
#define IOMMU_WRITE	BIT(1)

struct fw_rsc_devmem {
	uint32_t da;
	uint32_t pa;
	uint32_t len;
	uint32_t flags;
	uint32_t reserved;
	uint8_t name[32];
} __packed;

struct qcom_pas_data {
	uint32_t pas_id;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	enum qcom_clk_group clk_group;
};

TEE_Result pas_get_resource_table(uint32_t pas_id, struct resource_table *rt,
				  size_t *rt_size);

TEE_Result wpss_fw_start(struct qcom_pas_data *data);
TEE_Result wpss_fw_shutdown(struct qcom_pas_data *data);

TEE_Result compute_fw_start(struct qcom_pas_data *data);
TEE_Result compute_fw_shutdown(struct qcom_pas_data *data);

TEE_Result lpass_fw_start(struct qcom_pas_data *data);
TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data);

#endif /* _PAS_H_ */
