/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QTI_ICB_RPM_TYPES_H
#define QTI_ICB_RPM_TYPES_H

#ifdef CFG_QCOM_ICB_RPM

/* RPM_BUS_SLAVE_REQ fields. */
enum icb_rpm_slave_field {
	ICB_SLAVE_FIELD_BW = 0x00007762, /* 'bw\0\0' little endian */
};

/* RPM_BUS_MASTER_REQ fields. */
enum icb_rpm_master_bw_field {
	ICB_MASTER_FIELD_BW		= 0x00007762, /* 'bw\0\0' little endian */
	ICB_MASTER_FIELD_BW_THRESHOLD0	= 0x30747762, /* 'bwt0' little endian */
	ICB_MASTER_FIELD_BW_THRESHOLD1	= 0x31747762, /* 'bwt1' little endian */
	ICB_MASTER_FIELD_BW_THRESHOLD2	= 0x32747762, /* 'bwt2' little endian */
};

/*
 * RPM_BUS_SPDM_CLK_REQ field. Not currently issued by icbuarb.c — kept for
 * structural parity with the legacy field set.
 */
enum icb_rpm_spdm_clk_field {
	ICB_SPDM_CLK_FIELD_EN = 0x00006e65, /* 'en\0\0' little endian */
};

/*
 * RPM_BUS_MASTER_LATENCY_REQ field. Not currently issued by icbuarb.c —
 * kept for structural parity with the legacy field set.
 */
enum icb_rpm_latency_master_field {
	ICB_LATENCY_MASTER_FIELD_NS = 0x736e746c, /* 'ltns' little endian */
};
#endif /* CFG_QCOM_ICB_RPM */
#endif /* QTI_ICB_RPM_TYPES_H */
