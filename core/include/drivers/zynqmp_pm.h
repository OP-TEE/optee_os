/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021 Foundries.io Ltd
 */

#ifndef __DRIVERS_ZYNQMP_PM_H__
#define __DRIVERS_ZYNQMP_PM_H__

#include <drivers/zynqmp_efuse.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <util.h>

/*
 * Information about accessing eFuses and the Physically Uncloneable Function
 * (PUF) Support can be found at
 * https://www.xilinx.com/support/documentation/application_notes/xapp1319-zynq-usp-prog-nvm.pdf
 */
#define ZYNQMP_NONPUF_EFUSE		0
#define ZYNQMP_PUF_EFUSE		1

/* List of eFuse identifiers */
enum zynqmp_efuse_id {
	DNA = 0, IP_DISABLE, MISC_USER_CTRL, SEC_CTRL,
};

/* Valid bytes in the eFuse */
#define ZYNQMP_EFUSE_LEN(_id)	ZYNQMP_EFUSE_##_id##_LENGTH

/* Memory required to access the eFuse */
#define ZYNQMP_EFUSE_MEM(_id) (ROUNDUP(ZYNQMP_EFUSE_LEN(_id), CACHELINE_LEN))

/* Alignment required in the buffers used to read the eFuse */
#define __aligned_efuse __aligned(CACHELINE_LEN)

/*
 * Read eFuse memory
 * @buf: buffer, where eFuse date will be stored. The data is returned
 *       in LE byte order. The buffer address must be cached aligned
 * @buf_sz: buffer size in bytes, must be a multiple of the cacheline size
 * @id: eFuse identifier.
 * @puf: is eFuse PUF, ZYNQMP_PUF_EFUSE/ZYNQMP_NONPUF_EFUSE
 * Return a TEE_Result compliant status
 */
TEE_Result zynqmp_efuse_read(uint8_t *buf, size_t buf_sz,
			     enum zynqmp_efuse_id id, bool puf);

/*
 * Read the SoC version number:
 * Different eFuse bitfields carry different meaning depending on this version.
 */
TEE_Result zynqmp_soc_version(uint32_t *version);

#endif /*__DRIVERS_ZYNQMP_PM_H__*/
