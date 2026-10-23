// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "clk_cfg.h"
#include "clock_group.h"
#include "rail_vote.h"

/* Software source identities, indexing pll_votes[]. */
#define SRC_BI_TCXO		0
#define SRC_GPLL0_DIV2		1
#define SRC_GPLL6		2

#define QUP_SE_DFS_STATES	8
#define QUP_SE_MND_WIDTH	16

static const struct clk_mux_config qup_se_config[] = {
	{   7372800, SRC_GPLL0_DIV2, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  14745600, SRC_GPLL0_DIV2, 2,  768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  19200000, SRC_BI_TCXO,    2,    0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  29491200, SRC_GPLL0_DIV2, 2, 1536, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  32000000, SRC_GPLL0_DIV2, 2,    8,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  48000000, SRC_GPLL0_DIV2, 2,    4,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  64000000, SRC_GPLL0_DIV2, 2,   16,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  75000000, SRC_GPLL0_DIV2, 8,    0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  80000000, SRC_GPLL0_DIV2, 2,    4,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  96000000, SRC_GPLL0_DIV2, 2,    8,    25, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_GPLL0_DIV2, 6,    0,     0, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 102400000, SRC_GPLL0_DIV2, 2,  128,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_NOM },
	{ 112000000, SRC_GPLL0_DIV2, 2,   28,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_NOM },
	{ 117964800, SRC_GPLL0_DIV2, 2, 6144, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_NOM },
	{ 120000000, SRC_GPLL0_DIV2, 5,    0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_NOM },
	{ 128000000, SRC_GPLL6,      6,    0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_NOM },
};

static struct clk_regmap gcc_regmap = {
	.io.pa = GCC_BASE,
	.size = GCC_SIZE,
};

static const struct clk_pll_vote pll_votes[] = {
	{ "xo", NULL, 0, 0 },
	{ "gpll0_div2", &gcc_regmap, GCC_APCS_TZ_GPLL_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL0 },
	{ "gpll6", &gcc_regmap, GCC_APCS_TZ_GPLL_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL6 },
};

static const struct clk_parent_map parent_map_0[] = {
	{ SRC_BI_TCXO,    0 },
	{ SRC_GPLL0_DIV2, 2 },
	{ SRC_GPLL6,      6 },
};

#define QUP_SE_RCG(_idx) \
	{ \
		.name = "gcc_qupv3_wrap0_s" #_idx "_clk_src", \
		.regmap = &gcc_regmap, \
		.cmd_rcgr_addr = GCC_QUPV3_WRAP0_S##_idx##_CMD_RCGR, \
		.mnd_width = QUP_SE_MND_WIDTH, \
		.dfs_states = QUP_SE_DFS_STATES, \
		.configs = qup_se_config, \
		.n_configs = ARRAY_SIZE(qup_se_config), \
		.parent_map = parent_map_0, \
		.n_parents = ARRAY_SIZE(parent_map_0), \
	}

static const struct clk_rcg_desc gcc_qupv3_wrap0_s0_clk_src = QUP_SE_RCG(0);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s1_clk_src = QUP_SE_RCG(1);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s2_clk_src = QUP_SE_RCG(2);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s3_clk_src = QUP_SE_RCG(3);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s4_clk_src = QUP_SE_RCG(4);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s5_clk_src = QUP_SE_RCG(5);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s6_clk_src = QUP_SE_RCG(6);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s7_clk_src = QUP_SE_RCG(7);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s8_clk_src = QUP_SE_RCG(8);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s9_clk_src = QUP_SE_RCG(9);

#define BRANCH_CLK(_name, _cbcr, _vote_bit, _rcg) \
	{ \
		.name = (_name), \
		.regmap = &gcc_regmap, \
		.cbcr_addr = (_cbcr), \
		.clk_vote_addr = GCC_APCS_TZ_CLOCK_BRANCH_ENA_VOTE, \
		.vote_bit = (_vote_bit), \
		.rcg = (_rcg), \
	}

static const struct clk_branch_desc branches[] = {
	BRANCH_CLK("gcc_qupv3_wrap0_core_2x_clk",
		   GCC_QUPV3_WRAP0_CORE_2X_CBCR, QUPV3_WRAP0_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap0_core_clk",
		   GCC_QUPV3_WRAP0_CORE_CBCR, QUPV3_WRAP0_CORE_SHFT, NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_m_ahb_clk",
		   GCC_QUPV3_WRAP_0_M_AHB_CBCR, QUPV3_WRAP_0_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_s_ahb_clk",
		   GCC_QUPV3_WRAP_0_S_AHB_CBCR, QUPV3_WRAP_0_S_AHB_SHFT,
		   NULL),

	BRANCH_CLK("gcc_qupv3_wrap0_s0_clk", GCC_QUPV3_WRAP0_S0_CBCR,
		   QUPV3_WRAP0_S0_SHFT, &gcc_qupv3_wrap0_s0_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s1_clk", GCC_QUPV3_WRAP0_S1_CBCR,
		   QUPV3_WRAP0_S1_SHFT, &gcc_qupv3_wrap0_s1_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s2_clk", GCC_QUPV3_WRAP0_S2_CBCR,
		   QUPV3_WRAP0_S2_SHFT, &gcc_qupv3_wrap0_s2_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s3_clk", GCC_QUPV3_WRAP0_S3_CBCR,
		   QUPV3_WRAP0_S3_SHFT, &gcc_qupv3_wrap0_s3_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s4_clk", GCC_QUPV3_WRAP0_S4_CBCR,
		   QUPV3_WRAP0_S4_SHFT, &gcc_qupv3_wrap0_s4_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s5_clk", GCC_QUPV3_WRAP0_S5_CBCR,
		   QUPV3_WRAP0_S5_SHFT, &gcc_qupv3_wrap0_s5_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s6_clk", GCC_QUPV3_WRAP0_S6_CBCR,
		   QUPV3_WRAP0_S6_SHFT, &gcc_qupv3_wrap0_s6_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s7_clk", GCC_QUPV3_WRAP0_S7_CBCR,
		   QUPV3_WRAP0_S7_SHFT, &gcc_qupv3_wrap0_s7_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s8_clk", GCC_QUPV3_WRAP0_S8_CBCR,
		   QUPV3_WRAP0_S8_SHFT, &gcc_qupv3_wrap0_s8_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s9_clk", GCC_QUPV3_WRAP0_S9_CBCR,
		   QUPV3_WRAP0_S9_SHFT, &gcc_qupv3_wrap0_s9_clk_src),
};

static const struct clk_cfg shikra_clk_cfg = {
	.branches = branches,
	.n_branches = ARRAY_SIZE(branches),
	.pll_votes = pll_votes,
	.n_pll_votes = ARRAY_SIZE(pll_votes),
};

const struct clk_cfg *clk_get_cfg(void)
{
	IMSG("Shikra QUP clock debug marker: OP-TEE clock image is registered");

	return &shikra_clk_cfg;
}
