/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 * Copyright (c) 2018-2021, Arm Limited. All rights reserved.
 */

#ifndef __FFA_H
#define __FFA_H

/* This is based on the FF-A 1.0 EAC specification */

#include <smccc.h>
#include <stdint.h>

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
#define FFA_VERSION_MINOR		U(0)
#define FFA_VERSION_MINOR_SHIFT		U(0)
#define FFA_VERSION_MINOR_MASK		U(0xFFFF)
#define MAKE_FFA_VERSION(major, minor)	\
	((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
	 ((minor) & FFA_VERSION_MINOR_MASK))

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
#define FFA_MSG_WAIT			U(0x8400006B)
#define FFA_MSG_YIELD			U(0x8400006C)
#define FFA_MSG_RUN			U(0x8400006D)
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
#define FFA_SECONDARY_EP_REGISTER_64	U(0xC4000084)

/* Special value for traffic targeted to the Hypervisor or SPM */
#define FFA_TARGET_INFO_MBZ		U(0x0)

/* Memory attributes: Normal memory, Write-Back cacheable, Inner shareable */
#define FFA_NORMAL_MEM_REG_ATTR		U(0x2f)

/* Memory access permissions: Read-write */
#define FFA_MEM_ACC_RW			U(0x2)

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

/* Special value for MBZ parameters */
#define FFA_PARAM_MBZ			U(0x0)

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
struct ffa_mem_transaction {
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

/* Partition information descriptor */
struct ffa_partition_info {
	uint16_t id;
	uint16_t execution_context;
	uint32_t partition_properties;
};

/* Descriptor to relinquish a memory region (FFA_MEM_RELINQUISH) */
struct ffa_mem_relinquish {
	uint64_t handle;
	uint32_t flags;
	uint32_t endpoint_count;
	uint16_t endpoint_id_array[];
};
#endif /*__ASSEMBLER__*/
#endif /* __FFA_H */
