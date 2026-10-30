/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __FUSEPROV_V3_H
#define __FUSEPROV_V3_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define SECELF_SW_ID			0x2B

/* The MSB word of a row keeps 24 data bits, the rest holds the FEC bits */
#define FEC_MSB_DATA_MASK		GENMASK_32(23, 0)

#define OEM_PRODUCT_SEED_ROWS		5

#define TME_OEM_MRC_VECTOR_MASK	\
	(BIT32(QCOM_TME_OEM_MRC_VECTOR_BITS) - 1)

struct mem_region {
	uint32_t start_addr;
	uint32_t end_addr;
};

/*
 * Authenticate a sec.elf with TME-Lite, then program its fuse list, held in
 * non-secure memory at @secdat_pa. Fuses written before a failure stay.
 */
TEE_Result fuseprov_v3_blow_secelf(const void *elf, size_t elf_len,
				   paddr_t secdat_pa, size_t secdat_len);

#endif /* __FUSEPROV_V3_H */
