/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GPCE register definitions for Shikra.
 *
 * Address macros return a register offset with a zero base, or a virtual
 * address when supplied with the mapped CE or BAM base.
 */
#ifndef __GPCE_HWIO_H
#define __GPCE_HWIO_H

/* CE completion and error status registers */
#define CE_STATUS_ADDR(base)                   ((base) + 0x100)
#define CE_STATUS_MAC_FAILED_MASK              0x80000000
#define CE_STATUS_HSD_ERR_MASK                 0x100000
#define CE_STATUS_ACCESS_VIOL_MASK             0x80000
#define CE_STATUS_AXI_ERR_MASK                 0x4000
#define CE_STATUS_ENCR_BUSY_MASK               0x200
#define CE_STATUS_AUTH_BUSY_MASK               0x100
#define CE_STATUS_ERR_INTR_MASK                0x10
#define CE_STATUS_OPERATION_DONE_MASK          0x2
#define CE_STATUS_SW_ERR_MASK                  0x1

#define CE_STATUS2_ADDR(base)                  ((base) + 0x104)
#define CE_STATUS2_BIST_ERROR_MASK             0x80000000
#define CE_STATUS2_BIST_BUSY_MASK              0x40000000
#define CE_STATUS2_KEY_ERR_MASK                0x20000000
#define CE_STATUS2_AXI_EXTRA_MASK              0x2
#define CE_STATUS2_LOCKED_MASK                 0x1

#define CE_STATUS3_ADDR(base)                  ((base) + 0x11c)
#define CE_STATUS4_ADDR(base)                  ((base) + 0x124)

/* CE SHA authentication context and execution registers */
#define CE_SEG_SIZE_ADDR(base)                 ((base) + 0x110)
#define CE_GOPROC_ADDR(base)                   ((base) + 0x120)
#define CE_GOPROC_RESULTS_DUMP_MASK            0x4
#define CE_GOPROC_CLR_CNTXT_MASK               0x2
#define CE_GOPROC_GO_MASK                      0x1
#define CE_ENCR_SEG_CFG_ADDR(base)             ((base) + 0x200)
#define CE_AUTH_SEG_CFG_ADDR(base)             ((base) + 0x300)
#define CE_AUTH_SEG_CFG_FIRST_MASK             0x20000
#define CE_AUTH_SEG_CFG_LAST_MASK              0x10000
#define CE_AUTH_SEG_CFG_AUTH_POS_SHIFT         14
#define CE_AUTH_SEG_CFG_AUTH_SIZE_SHIFT        9
#define CE_AUTH_SEG_CFG_AUTH_ALG_SHIFT         0
#define CE_AUTH_SEG_CFG_AUTH_ALG_SHA256        1
#define CE_AUTH_SEG_SIZE_ADDR(base)            ((base) + 0x304)
#define CE_AUTH_SEG_START_ADDR(base)           ((base) + 0x308)
#define CE_AUTH_IVn_ADDR(base, n)              ((base) + 0x310 + 0x4 * (n))
#define CE_AUTH_BYTECNT0_ADDR(base)            ((base) + 0x390)
#define CE_AUTH_BYTECNTn_ADDR(base, n)         \
	(CE_AUTH_BYTECNT0_ADDR(base) + sizeof(uint32_t) * (n))

/* CE transfer configuration register */
#define CE_CONFIG_ADDR(base)                   ((base) + 0x400)
#define CE_CONFIG_REQ_SIZE_MASK                0x1e0000
#define CE_CONFIG_LITTLE_ENDIAN_MODE_MASK      0x200
#define CE_CONFIG_PIPE_SET_SELECT_SHIFT        5
#define CE_CONFIG_HIGH_SPD_DATA_EN_N_MASK      0x10
#define CE_CONFIG_MASK_DOUT_INTR_MASK          0x8
#define CE_CONFIG_MASK_DIN_INTR_MASK           0x4
#define CE_CONFIG_MASK_OP_DONE_INTR_MASK       0x2

#endif /* __GPCE_HWIO_H */
