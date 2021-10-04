/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2021
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef __DRIVERS_ZYNQMP_CSUDMA_H_
#define __DRIVERS_ZYNQMP_CSUDMA_H_

#include <drivers/zynqmp_csu.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define ZYNQMP_CSUDMA_ALIGN			64
#define __aligned_csudma			__aligned(ZYNQMP_CSUDMA_ALIGN)

#define ZYNQMP_CSUDMA_MIN_SIZE			16
#define ZYNQMP_CSUDMA_DONE			BIT(0)

enum zynqmp_csudma_channel {
	ZYNQMP_CSUDMA_SRC_CHANNEL = 0,
	ZYNQMP_CSUDMA_DST_CHANNEL
};

TEE_Result zynqmp_csudma_transfer(enum zynqmp_csudma_channel channel,
				  void *address, size_t len, uint8_t notify);
TEE_Result zynqmp_csudma_sync(enum zynqmp_csudma_channel channel);
TEE_Result zynqmp_csudma_prepare(void);
void zynqmp_csudma_unprepare(void);

#endif
