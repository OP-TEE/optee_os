/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QTI_ICB_V2_ICBID_H
#define QTI_ICB_V2_ICBID_H

/*
 * Legacy icb_v2/icbid.h defined ~270 master and ~355 slave IDs spanning
 * chip generations back to ~2010. Trimmed here to the subset actually
 * referenced by shikra/u_data.c, with each value assigned explicitly
 * from the legacy icbid_rpm.h enum so IDs stay stable regardless of
 * which entries are present in this curated subset.
 */
enum icbid_master {
	ICBID_MASTER_APPSS_PROC = 0,
	ICBID_MASTER_CRYPTO_CORE0 = 23,
	ICBID_MASTER_SNOC_CNOC = 52,
	ICBID_MASTER_LLCC = 190,
	ICBID_MASTER_SNOC_SF_MEM_NOC = 76,
	ICBID_MASTER_ANOC_SNOC = 110,
	ICBID_MASTER_MEMNOC_SNOC = 184,
	ICBID_MASTER_CRVIRT_A1NOC = 136,
	ICBID_MASTER_QUP_0 = 166,
	ICBID_MASTER_QUP_CORE_0 = 170,
	ICBID_MASTER_HWKM_CORE = 174,
	ICBID_MASTER_PKA_CORE = 175,
	ICBID_MASTER_COUNT = 199,
	ICBID_MASTER_NONE = ICBID_MASTER_COUNT,
	ICBID_MASTER_SIZE = 0x7FFFFFFF
};

enum icbid_slave {
	ICBID_SLAVE_EBI1 = 0,
	ICBID_SLAVE_SNOC_CNOC = 25,
	ICBID_SLAVE_IMEM = 26,
	ICBID_SLAVE_ANOC_SNOC = 141,
	ICBID_SLAVE_CRYPTO_0_CFG = 52,
	ICBID_SLAVE_HWKM = 44,
	ICBID_SLAVE_QUP_0 = 261,
	ICBID_SLAVE_LLCC = 312,
	ICBID_SLAVE_MEMNOC_SNOC = 314,
	ICBID_SLAVE_MEMNOC_SF = 313,
	ICBID_SLAVE_HWKM_CORE = 280,
	ICBID_SLAVE_PKA_CORE = 281,
	ICBID_SLAVE_PKA_WRAPPER_CFG = 282,
	ICBID_SLAVE_QUP_CORE_0 = 264,
	ICBID_SLAVE_CRVIRT_A1NOC = 199,
	ICBID_SLAVE_COUNT = 330,
	ICBID_SLAVE_NONE = ICBID_SLAVE_COUNT,
	ICBID_SLAVE_SIZE = 0x7FFFFFFF
};

#endif /* QTI_ICB_V2_ICBID_H */
