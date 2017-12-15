/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __PTA_SECSTOR_TA_MGMT_H
#define __PTA_SECSTOR_TA_MGMT_H

/*
 * Bootstrap (install initial) Trusted Application or Secure Domain into
 * secure storage from a signed binary.
 *
 * [in]		memref[0]: signed binary
 */
#define PTA_SECSTOR_TA_MGMT_BOOTSTRAP	0

#define PTA_SECSTOR_TA_MGMT_UUID { 0x6e256cba, 0xfc4d, 0x4941, { \
				   0xad, 0x09, 0x2c, 0xa1, 0x86, 0x03, 0x42, \
				   0xdd } }

#endif /*__PTA_SECSTOR_TA_MGMT_H*/
