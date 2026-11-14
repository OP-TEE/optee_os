/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QTI_ICBID_H
#define QTI_ICBID_H
#ifdef CFG_QCOM_ICB_RPM
#include <drivers/qcom/icb/icbid_rpm.h>
#else
enum icbid_master {
	ICBID_MASTER_LLCC = 0,
	ICBID_MASTER_A1NOC_TILE_HSCNOC,
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_MASTER_CRYPTO_CORE1,
	ICBID_MASTER_CRYPTO_CORE2,
	ICBID_MASTER_COUNT,
	ICBID_MASTER_NONE = ICBID_MASTER_COUNT,
	ICBID_MASTER_SIZE = 0x7FFFFFFF /**< Force to 32 bits */
};

enum icbid_slave {
	ICBID_SLAVE_EBI1 = 0,
	ICBID_SLAVE_A1NOC_HSCNOC,
	ICBID_SLAVE_LLCC,
	ICBID_SLAVE_COUNT,
	ICBID_SLAVE_NONE = ICBID_SLAVE_COUNT,
	ICBID_SLAVE_SIZE = 0x7FFFFFFF /**< Force to 32 bits */
};
#endif
#endif /* QTI_ICBID_H */
