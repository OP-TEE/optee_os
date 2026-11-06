/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PTA_QCOM_FUSEPROV_H
#define __PTA_QCOM_FUSEPROV_H

#include <stdint.h>

/* Pseudo TA provisioning the fuses of SoCs where TME-Lite owns the QFPROM */

#define PTA_QCOM_FUSEPROV_UUID { 0x7e5e8c5d, 0x5375, 0x4ab0, \
		{ 0x8b, 0x11, 0x95, 0x14, 0x96, 0x65, 0xdc, 0x88 } }

/* Physical memory range holding the fuse list segment of the sec.elf */
struct pta_qcom_fuseprov_region {
	uint64_t start;
	uint64_t end;
};

/*
 * Blow the fuses of a sec.elf: [in] params[0].memref ELF metadata, [in]
 * params[1].memref one fuse list region, [out] params[2].value.a TEE_Result
 */
#define PTA_QCOM_FUSEPROV_BLOW_SECELF	0

#endif /* __PTA_QCOM_FUSEPROV_H */
