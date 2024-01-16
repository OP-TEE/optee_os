/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2018-2023, Arm Limited. All rights reserved.
 */

#ifndef __FFA_H
#define __FFA_H

/* This is based on the FF-A 1.0 EAC specification */

#include <smccc.h>
#include <stdint.h>
#include <util.h>

/* Error codes */
#define FFA_OK			0
#define FFA_NOT_SUPPORTED	-1
#define FFA_INVALID_PARAMETERS	-2
#define FFA_NO_MEMORY		-3
#define FFA_BUSY		-4
#define FFA_INTERRUPTED		-5
#define FFA_DENIED		-6
#define FFA_RETRY		-7
#define FFA_ABORTED		-8

/* FFA_VERSION helpers */
#define FFA_VERSION_MAJOR		U(1)
#define FFA_VERSION_MAJOR_SHIFT		U(16)
#define FFA_VERSION_MAJOR_MASK		U(0x7FFF)
#define FFA_VERSION_MINOR		U(1)
#define FFA_VERSION_MINOR_SHIFT		U(0)
#define FFA_VERSION_MINOR_MASK		U(0xFFFF)
#define MAKE_FFA_VERSION(major, minor)	\
	((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
	 ((minor) & FFA_VERSION_MINOR_MASK))

#define FFA_VERSION_1_0			MAKE_FFA_VERSION(1, 0)
#define FFA_VERSION_1_1			MAKE_FFA_VERSION(1, 1)

/* Function IDs */
#define FFA_ERROR			U(0x84000060)
#define FFA_SUCCESS_32			U(0x84000061)
#define FFA_SUCCESS_64			U(0xC4000061)
#define FFA_INTERRUPT			U(0x84000062)
#define FFA_VERSION			U(0x84000063)
#define FFA_FEATURES			U(0x84000064)
#define FFA_RX_RELEASE			U(0x84000065)
#define FFA_RXTX_MAP_32			U(0x84000066)
#define FFA_RXTX_MAP_64			U(0xC4000066)
#define FFA_RXTX_UNMAP			U(0x84000067)
#define FFA_PARTITION_INFO_GET		U(0x84000068)
#define FFA_ID_GET			U(0x84000069)
#define FFA_SPM_ID_GET			U(0x84000085)
#define FFA_MSG_WAIT			U(0x8400006B)
#define FFA_MSG_YIELD			U(0x8400006C)
#define FFA_RUN				U(0x8400006D)
#define FFA_MSG_SEND2			U(0x84000086)
#define FFA_MSG_SEND			U(0x8400006E)
#define FFA_MSG_SEND_DIRECT_REQ_32	U(0x8400006F)
#define FFA_MSG_SEND_DIRECT_REQ_64	U(0xC400006F)
#define FFA_MSG_SEND_DIRECT_RESP_32	U(0x84000070)
#define FFA_MSG_SEND_DIRECT_RESP_64	U(0xC4000070)
#define FFA_MSG_POLL			U(0x8400006A)
#define FFA_MEM_DONATE_32		U(0x84000071)
#define FFA_MEM_DONATE_64		U(0xC4000071)
#define FFA_MEM_LEND_32			U(0x84000072)
#define FFA_MEM_LEND_64			U(0xC4000072)
#define FFA_MEM_SHARE_32		U(0x84000073)
#define FFA_MEM_SHARE_64		U(0xC4000073)
#define FFA_MEM_RETRIEVE_REQ_32		U(0x84000074)
#define FFA_MEM_RETRIEVE_REQ_64		U(0xC4000074)
#define FFA_MEM_RETRIEVE_RESP		U(0x84000075)
#define FFA_MEM_RELINQUISH		U(0x84000076)
#define FFA_MEM_RECLAIM			U(0x84000077)
#define FFA_MEM_FRAG_RX			U(0x8400007A)
#define FFA_MEM_FRAG_TX			U(0x8400007B)
#define FFA_NORMAL_WORLD_RESUME		U(0x8400007C)
#define FFA_NOTIFICATION_BITMAP_CREATE	U(0x8400007D)
#define FFA_NOTIFICATION_BITMAP_DESTROY	U(0x8400007E)
#define FFA_NOTIFICATION_BIND		U(0x8400007F)
#define FFA_NOTIFICATION_UNBIND		U(0x84000080)
#define FFA_NOTIFICATION_SET		U(0x84000081)
#define FFA_NOTIFICATION_GET		U(0x84000082)
#define FFA_NOTIFICATION_INFO_GET_32	U(0x84000083)
#define FFA_NOTIFICATION_INFO_GET_64	U(0xC4000083)
#define FFA_SECONDARY_EP_REGISTER_64	U(0xC4000087)
#define FFA_MEM_PERM_GET_32		U(0x84000088)
#define FFA_MEM_PERM_GET_64		U(0xC4000088)
#define FFA_MEM_PERM_SET_32		U(0x84000089)
#define FFA_MEM_PERM_SET_64		U(0xC4000089)
#define FFA_CONSOLE_LOG_32		U(0x8400008A)
#define FFA_CONSOLE_LOG_64		U(0xC400008A)

#define FFA_FEATURES_FUNC_ID_MASK	BIT32(31)
#define FFA_FEATURES_FEATURE_ID_MASK	GENMASK_32(7, 0)

#define FFA_FEATURE_NOTIF_PEND_INTR	U(0x1)
#define FFA_FEATURE_SCHEDULE_RECV_INTR	U(0x2)
#define FFA_FEATURE_MANAGED_EXIT_INTR	U(0x3)

/* Special value for traffic targeted to the Hypervisor or SPM */
#define FFA_TARGET_INFO_MBZ		U(0x0)

#define FFA_MSG_FLAG_FRAMEWORK		BIT(31)
#define FFA_MSG_TYPE_MASK		GENMASK_32(7, 0)
#define FFA_MSG_PSCI			U(0x0)
#define FFA_MSG_SEND_VM_CREATED		U(0x4)
#define FFA_MSG_RESP_VM_CREATED		U(0x5)
#define FFA_MSG_SEND_VM_DESTROYED	U(0x6)
#define FFA_MSG_RESP_VM_DESTROYED	U(0x7)
#define FFA_MSG_VERSION_REQ		U(0x8)
#define FFA_MSG_VERSION_RESP		U(0x9)

/*
 * Flag used as parameter to FFA_PARTITION_INFO_GET to return partition
 * count only.
 */
#define FFA_PARTITION_INFO_GET_COUNT_FLAG	BIT(0)

/* Memory attributes: Normal memory, Write-Back cacheable, Inner shareable */
#define FFA_NORMAL_MEM_REG_ATTR		U(0x2f)

/* Memory access permissions: Read-write */
#define FFA_MEM_ACC_RW			BIT(1)

/* Memory access permissions: executable */
#define FFA_MEM_ACC_EXE			BIT(3)

/* Memory access permissions mask */
#define FFA_MEM_ACC_MASK		0xf

/* Clear memory before mapping in receiver */
#define FFA_MEMORY_REGION_FLAG_CLEAR		BIT(0)
/* Relayer may time slice this operation */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE	BIT(1)
/* Clear memory after receiver relinquishes it */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH	BIT(2)

/* Share memory transaction */
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE SHIFT_U32(1, 3)
/* Relayer must choose the alignment boundary */
#define FFA_MEMORY_REGION_FLAG_ANY_ALIGNMENT	0

#define FFA_MEM_PERM_DATA_PERM		GENMASK_32(1, 0)
#define FFA_MEM_PERM_RW			U(0x1)
#define FFA_MEM_PERM_RO			U(0x3)

#define FFA_MEM_PERM_INSTRUCTION_PERM	BIT(2)
#define FFA_MEM_PERM_NX			BIT(2)
#define FFA_MEM_PERM_X			U(0)

#define FFA_MEM_PERM_RESERVED		GENMASK_32(31, 3)

/* Special value for MBZ parameters */
#define FFA_PARAM_MBZ			U(0x0)

/*
 * The W1 register in FFA_INTERRUPT and FFA_RUN interfaces contains the target
 * information. This value has two parts, the SP ID and vCPU ID. The SP ID
 * identifies the SP to resume and the vCPU ID identifies the vCPU or execution
 * context to resume (FF-A v1.1 section 4.8).
 */
#define FFA_TARGET_INFO_SET(sp_id, vcpu_id)	(((sp_id) << 16) | (vcpu_id))
#define FFA_TARGET_INFO_GET_SP_ID(info)		(((info) >> 16) & 0xffff)
#define FFA_TARGET_INFO_GET_VCPU_ID(info)	((info) & 0xffff)

/*
 * Flags used for the FFA_PARTITION_INFO_GET return message:
 * BIT(0): Supports receipt of direct requests
 * BIT(1): Can send direct requests
 * BIT(2): Can send and receive indirect messages
 * BIT(3): Supports receipt of notifications
 * BIT(4-5): Partition ID is a PE endpoint ID
 */
#define FFA_PART_PROP_DIRECT_REQ_RECV	BIT(0)
#define FFA_PART_PROP_DIRECT_REQ_SEND	BIT(1)
#define FFA_PART_PROP_INDIRECT_MSGS	BIT(2)
#define FFA_PART_PROP_RECV_NOTIF	BIT(3)
#define FFA_PART_PROP_IS_PE_ID		SHIFT_U32(0, 4)
#define FFA_PART_PROP_IS_SEPID_INDEP	SHIFT_U32(1, 4)
#define FFA_PART_PROP_IS_SEPID_DEP	SHIFT_U32(2, 4)
#define FFA_PART_PROP_IS_AUX_ID		SHIFT_U32(3, 4)
#define FFA_PART_PROP_NOTIF_CREATED	BIT(6)
#define FFA_PART_PROP_NOTIF_DESTROYED	BIT(7)
#define FFA_PART_PROP_AARCH64_STATE	BIT(8)

#define FFA_MEMORY_HANDLE_HYPERVISOR_BIT	BIT64(63)
#define FFA_MEMORY_HANDLE_SECURE_BIT		BIT64(45)
#define FFA_MEMORY_HANDLE_NON_SECURE_BIT	BIT64(44)
/*
 * Codes the OP-TEE partition/guest ID into a cookie in order to know which
 * partition to activate when reclaiming the shared memory. This field is 0
 * unless CFG_NS_VIRTUALIZATION is enabled.
 */
#define FFA_MEMORY_HANDLE_PRTN_SHIFT		16
#define FFA_MEMORY_HANDLE_PRTN_MASK		GENMASK_32(16, 0)


#define FFA_BOOT_INFO_NAME_LEN		U(16)

/* Boot Info descriptors type */
#define FFA_BOOT_INFO_TYPE_IMDEF	BIT(7)
#define FFA_BOOT_INFO_TYPE_ID_MASK	GENMASK_32(6, 0)
#define FFA_BOOT_INFO_TYPE_ID_FDT	U(0)
#define FFA_BOOT_INFO_TYPE_ID_HOB	U(1)

/* Boot Info descriptors flags */
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_MASK	GENMASK_32(1, 0)
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_STRING	U(0)
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_UUID	U(1)

/** Bits [3:2] encode the format of the content field in ffa_boot_info_desc. */
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT U(2)
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK	GENMASK_32(3, 2)
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_VALUE	U(1)
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR	U(0)

#define FFA_BOOT_INFO_SIGNATURE		U(0xFFA)
#define FFA_BOOT_INFO_VERSION		U(0x10001)

#define FFA_CONSOLE_LOG_CHAR_COUNT_MASK	GENMASK_32(7, 0)
#define FFA_CONSOLE_LOG_32_MAX_MSG_LEN	U(24)
#define FFA_CONSOLE_LOG_64_MAX_MSG_LEN	U(48)

#ifndef __ASSEMBLER__
/* Constituent memory region descriptor */
struct ffa_address_range {
	uint64_t address;
	uint32_t page_count;
	uint32_t reserved;
};

/* Composite memory region descriptor */
struct ffa_mem_region {
	uint32_t total_page_count;
	uint32_t address_range_count;
	uint64_t reserved;
	struct ffa_address_range address_range_array[];
};

/* Memory access permissions descriptor */
struct ffa_mem_access_perm {
	uint16_t endpoint_id;
	uint8_t perm;
	uint8_t flags;
};

/* Endpoint memory access descriptor */
struct ffa_mem_access {
	struct ffa_mem_access_perm access_perm;
	uint32_t region_offs;
	uint64_t reserved;
};

/* Lend, donate or share memory transaction descriptor */
struct ffa_mem_transaction_1_0 {
	uint16_t sender_id;
	uint8_t mem_reg_attr;
	uint8_t reserved0;
	uint32_t flags;
	uint64_t global_handle;
	uint64_t tag;
	uint32_t reserved1;
	uint32_t mem_access_count;
	struct ffa_mem_access mem_access_array[];
};

struct ffa_mem_transaction_1_1 {
	uint16_t sender_id;
	uint16_t mem_reg_attr;
	uint32_t flags;
	uint64_t global_handle;
	uint64_t tag;
	uint32_t mem_access_size;
	uint32_t mem_access_count;
	uint32_t mem_access_offs;
	uint8_t reserved[12];
};

/*
 * The parts needed from struct ffa_mem_transaction_1_0 or struct
 * ffa_mem_transaction_1_1, used to provide an abstraction of difference in
 * data structures between version 1.0 and 1.1. This is just an internal
 * interface and can be changed without changing any ABI.
 */
struct ffa_mem_transaction_x {
	uint16_t sender_id;
	uint8_t mem_reg_attr;
	uint8_t flags;
	uint8_t mem_access_size;
	uint8_t mem_access_count;
	uint16_t mem_access_offs;
	uint64_t global_handle;
	uint64_t tag;
};

#define FFA_UUID_SIZE		16

/* Partition information descriptor */
struct ffa_partition_info_x {
	uint16_t id;
	uint16_t execution_context;
	uint32_t partition_properties;
	/*
	 * The uuid field is absent in FF-A 1.0, and an array of 16
	 * (FFA_UUID_SIZE) from FF-A 1.1
	 */
	uint8_t uuid[];
};

/* Descriptor to relinquish a memory region (FFA_MEM_RELINQUISH) */
struct ffa_mem_relinquish {
	uint64_t handle;
	uint32_t flags;
	uint32_t endpoint_count;
	uint16_t endpoint_id_array[];
};

/* FF-A v1.0 boot information name-value pairs */
struct ffa_boot_info_nvp_1_0 {
	uint32_t name[4];
	uint64_t value;
	uint64_t size;
};

/* FF-A v1.0 boot information descriptor */
struct ffa_boot_info_1_0 {
	uint32_t magic;
	uint32_t count;
	struct ffa_boot_info_nvp_1_0 nvp[];
};

/* FF-A v1.1 boot information descriptor */
struct ffa_boot_info_1_1 {
	char name[FFA_BOOT_INFO_NAME_LEN];
	uint8_t type;
	uint8_t reserved;
	uint16_t flags;
	uint32_t size;
	uint64_t contents;
};

/* FF-A v1.1 boot information header */
struct ffa_boot_info_header_1_1 {
	uint32_t signature;
	uint32_t version;
	uint32_t blob_size;
	uint32_t desc_size;
	uint32_t desc_count;
	uint32_t desc_offset;
	uint64_t reserved;
};

#endif /*__ASSEMBLER__*/
#endif /* __FFA_H */
