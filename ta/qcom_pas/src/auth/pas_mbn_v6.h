/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_MBN_V6_H
#define __PAS_MBN_V6_H

#include <stdint.h>

struct pas_mbn_v6_header {
	uint32_t reserved0;
	uint32_t version;
	uint32_t qti_signature_size;
	uint32_t qti_cert_chain_size;
	uint32_t image_size;
	uint32_t code_size;
	uint32_t reserved1;
	uint32_t oem_signature_size;
	uint32_t reserved2;
	uint32_t oem_cert_chain_size;
	uint32_t qti_metadata_size;
	uint32_t oem_metadata_size;
};

#endif /* __PAS_MBN_V6_H */
