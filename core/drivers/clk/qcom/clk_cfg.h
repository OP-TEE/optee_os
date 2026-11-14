/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLK_CFG_H_
#define _CLK_CFG_H_

#include <mm/core_memprot.h>
#include <stdint.h>
#include <types_ext.h>

/* configs[] must be sorted ascending by freq_hz. */
struct clk_mux_config {
	uint32_t freq_hz;
	uint8_t  src;		/* sw id, matched against parent_map[].src */
	uint16_t div2x;		/* 2x half-int SRC_DIV; SRC_DIV = div2x - 1 */
	uint32_t m;
	uint32_t n;		/* MND divider; used only when m && m < n */
	uint8_t  dfs_idx;	/* DFS perf-state index, or CLK_DFS_NA */
	uint16_t corner;	/* RAIL_VOLTAGE_LEVEL_* this rate needs, or 0 */
};

#define CLK_DFS_NA		0xFF

/* RCG register layout; offsets relative to clk_rcg_desc.cmd_rcgr_addr. */
#define QCOM_RCG_CFG_REG_OFFSET			0x4
#define QCOM_RCG_M_REG_OFFSET			0x8
#define QCOM_RCG_N_REG_OFFSET			0xC
#define QCOM_RCG_D_REG_OFFSET			0x10
#define QCOM_RCG_CMD_DFSR_REG_OFFSET		0x14
#define QCOM_RCG_PERF_DFSR_REG_OFFSET		0x1C
#define QCOM_RCG_PERF_M_DFSR_REG_OFFSET		0x5C
#define QCOM_RCG_PERF_N_DFSR_REG_OFFSET		0x9C
#define QCOM_RCG_PERF_D_DFSR_REG_OFFSET		0xDC

/* CMD_RCGR fields. */
#define QCOM_RCG_CMD_CFG_UPDATE_FMSK		0x00000001

/* CFG_RCGR fields. */
#define QCOM_RCG_CFG_HW_CLK_CONTROL_FMSK	0x00100000
#define QCOM_RCG_CFG_MODE_FMSK			0x00003000
#define QCOM_RCG_CFG_MODE_SHFT			12
#define QCOM_RCG_CFG_SRC_SEL_FMSK		0x00000700
#define QCOM_RCG_CFG_SRC_SEL_SHFT		8
#define QCOM_RCG_CFG_SRC_DIV_FMSK		0x0000001F
#define QCOM_RCG_CFG_SRC_DIV_SHFT		0
#define QCOM_RCG_CFG_DUAL_EDGE_MODE_VAL		0x2

/* CMD_DFSR fields. */
#define QCOM_RCG_CMD_DFSR_HW_CLK_CONTROL_FMSK	0x00000020
#define QCOM_RCG_CMD_DFSR_DFS_EN_FMSK		0x00000001
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_FMSK	0x00007800
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_SHFT	11

/* One MMIO block a domain's registers live in, e.g. one GCC instance. */
struct clk_regmap {
	struct io_pa_va io;
	size_t size;
};

/* Maps one RCG's own hardware SRC_SEL encoding to a source clk. */
struct clk_parent_map {
	uint8_t src;		/* index into clk_cfg.pll_votes[] */
	uint8_t mux_sel;	/* this RCG's SRC_SEL value for that source */
};

/* An RCG (mux/divider/DFS block), registered as its own struct clk. */
struct clk_rcg_desc {
	const char *name;
	struct clk_regmap *regmap;
	paddr_t cmd_rcgr_addr;
	uint16_t mnd_width;	/* 0 if this RCG has no M/N/D hardware */
	uint16_t dfs_states;	/* DFS perf states supported; 0 means no DFS */
	const struct clk_mux_config *configs;
	uint32_t n_configs;
	const struct clk_parent_map *parent_map;
	uint8_t n_parents;	/* count of parent_map[]/parents[] entries */
};

/* A CBCR branch gate, registered as its own struct clk. */
struct clk_branch_desc {
	const char *name;
	struct clk_regmap *regmap;
	paddr_t cbcr_addr;
	paddr_t clk_vote_addr;	/* shared vote register; 0 for none */
	uint8_t vote_bit;
	const struct clk_rcg_desc *rcg;	/* parent RCG, or NULL if branch-only */
};

/* One RCG source, its own struct clk; direct reg write, not RPMh. */
struct clk_pll_vote {
	const char *name;
	struct clk_regmap *regmap;
	paddr_t vote_reg_addr;	/* 0 means enable/disable no-op (e.g. XO) */
	uint8_t vote_bit;
};

/* RPM resource that can be voted by name through qcom_clk_rpm_request(). */
struct qcom_clk_rpm_resource {
	const char *name;
	uint32_t key;
	uint32_t resource;
	uint32_t id;
};

/* Per-target config; combined branches point @rcg at own clk_rcg_desc. */
struct clk_cfg {
	const struct clk_branch_desc *branches;
	uint32_t n_branches;
	const struct clk_pll_vote *pll_votes;
	uint32_t n_pll_votes;
	const struct qcom_clk_rpm_resource *rpm_resources;
	uint32_t n_rpm_resources;
};

const struct clk_cfg *clk_get_cfg(void);

#endif /* _CLK_CFG_H_ */
