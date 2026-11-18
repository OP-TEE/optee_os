/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <util.h>

#include "clk_cfg.h"
#include "clock_group.h"
#include "rail_vote.h"

/* Software source identities, indexing pll_votes[]. */
#define SRC_GPLL0                0
#define SRC_GPLL0_OUT_EVEN       1
#define SRC_XO                   2

#define QUP_SE_DFS_STATES	8

/*
 * Frequency plan for qup_se_100mhz.
 * Max frequency: 100 MHz.
 */
static const struct clk_mux_config qup_se_100mhz[] = {
	{    7372800, SRC_GPLL0_OUT_EVEN  ,  2,   384, 15625, CLK_DFS_NA, 0 },
	{   14745600, SRC_GPLL0_OUT_EVEN  ,  2,   768, 15625, CLK_DFS_NA, 0 },
	{   19200000, SRC_XO              ,  2,     0,     0, 0x00,       0 },
	{   29491200, SRC_GPLL0_OUT_EVEN  ,  2,  1536, 15625, CLK_DFS_NA, 0 },
	{   32000000, SRC_GPLL0_OUT_EVEN  ,  2,     8,    75, 0x01,       0 },
	{   48000000, SRC_GPLL0_OUT_EVEN  ,  2,     4,    25, 0x02,       0 },
	{   51200000, SRC_GPLL0_OUT_EVEN  ,  2,    64,   375, CLK_DFS_NA, 0 },
	{   64000000, SRC_GPLL0_OUT_EVEN  ,  2,    16,    75, 0x03,       0 },
	{   75000000, SRC_GPLL0_OUT_EVEN  ,  8,     0,     0, CLK_DFS_NA, 0 },
	{   80000000, SRC_GPLL0_OUT_EVEN  ,  2,     4,    15, 0x04,       0 },
	{   96000000, SRC_GPLL0_OUT_EVEN  ,  2,     8,    25, 0x05,       0 },
	{  100000000, SRC_GPLL0_OUT_EVEN  ,  6,     0,     0, 0x06,       0 },
};

/*
 * Frequency plan for qup_se_150mhz.
 * Max frequency: 150 MHz.
 */
static const struct clk_mux_config qup_se_150mhz[] = {
	{    7372800, SRC_GPLL0_OUT_EVEN  ,  2,   384, 15625, CLK_DFS_NA, 0 },
	{   14745600, SRC_GPLL0_OUT_EVEN  ,  2,   768, 15625, CLK_DFS_NA, 0 },
	{   19200000, SRC_XO              ,  2,     0,     0, 0x00,       0 },
	{   29491200, SRC_GPLL0_OUT_EVEN  ,  2,  1536, 15625, CLK_DFS_NA, 0 },
	{   32000000, SRC_GPLL0_OUT_EVEN  ,  2,     8,    75, 0x01,       0 },
	{   48000000, SRC_GPLL0_OUT_EVEN  ,  2,     4,    25, 0x02,       0 },
	{   51200000, SRC_GPLL0_OUT_EVEN  ,  2,    64,   375, CLK_DFS_NA, 0 },
	{   64000000, SRC_GPLL0_OUT_EVEN  ,  2,    16,    75, 0x03,       0 },
	{   75000000, SRC_GPLL0_OUT_EVEN  ,  8,     0,     0, CLK_DFS_NA, 0 },
	{   80000000, SRC_GPLL0_OUT_EVEN  ,  2,     4,    15, CLK_DFS_NA, 0 },
	{   96000000, SRC_GPLL0_OUT_EVEN  ,  2,     8,    25, 0x04,       0 },
	{  100000000, SRC_GPLL0           , 12,     0,     0, 0x05,       0 },
	{  102400000, SRC_GPLL0_OUT_EVEN  ,  2,   128,   375, CLK_DFS_NA, 0 },
	{  112000000, SRC_GPLL0_OUT_EVEN  ,  2,    28,    75, CLK_DFS_NA, 0 },
	{  117964800, SRC_GPLL0_OUT_EVEN  ,  2,  6144, 15625, CLK_DFS_NA, 0 },
	{  120000000, SRC_GPLL0           , 10,     0,     0, 0x06,       0 },
	{  150000000, SRC_GPLL0_OUT_EVEN  ,  4,     0,     0, 0x07,       0 },
};

/*
 * Frequency plan for qup_se_200mhz.
 * Max frequency: 200 MHz.
 */
static const struct clk_mux_config qup_se_200mhz[] = {
	{   19200000, SRC_XO              ,  2,     0,     0, 0x00,       0 },
	{  200000000, SRC_GPLL0_OUT_EVEN  ,  3,     0,     0, 0x02,       0 },
};

static struct clk_regmap gcc_regmap = {
	.io.pa = GCC_BASE,
	.size = GCC_SIZE,
};

static const struct clk_pll_vote pll_votes[] = {
	{ "gpll0", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL0 },
	{ "gpll0_out_even", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL0 },
	{ "xo", NULL, 0, 0 },
};

/*
 * Mux_sel values are this wrapper's own SRC_SEL encoding.
 */
static const struct clk_parent_map parent_map_0[] = {
	{ SRC_XO, 0 },
	{ SRC_GPLL0, 1 },
	{ SRC_GPLL0_OUT_EVEN, 6 },
};

/* RCGs -- one named instance per QUP SE index that needs rate control. */
#define QUP_SE_MND_WIDTH	16

#define QUP_SE_RCG(_name, _cmd_rcgr, _plan)			\
	{								\
		.name = (_name),					\
		.regmap = &gcc_regmap,					\
		.cmd_rcgr_addr = (_cmd_rcgr),				\
		.mnd_width = QUP_SE_MND_WIDTH,				\
		.dfs_states = QUP_SE_DFS_STATES,			\
		.configs = (_plan),					\
		.n_configs = ARRAY_SIZE(_plan),				\
		.parent_map = parent_map_0,				\
		.n_parents = ARRAY_SIZE(parent_map_0),			\
	}

static const struct clk_rcg_desc gcc_qupv3_wrap0_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s0_clk_src",
		   GCC_QUPV3_WRAP0_S0_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s1_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s1_clk_src",
		   GCC_QUPV3_WRAP0_S1_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s2_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s2_clk_src",
		   GCC_QUPV3_WRAP0_S2_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s3_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s3_clk_src",
		   GCC_QUPV3_WRAP0_S3_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s4_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s4_clk_src",
		   GCC_QUPV3_WRAP0_S4_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s5_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s5_clk_src",
		   GCC_QUPV3_WRAP0_S5_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s0_clk_src",
		   GCC_QUPV3_WRAP1_S0_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s1_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s1_clk_src",
		   GCC_QUPV3_WRAP1_S1_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s2_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s2_clk_src",
		   GCC_QUPV3_WRAP1_S2_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s3_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s3_clk_src",
		   GCC_QUPV3_WRAP1_S3_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s4_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s4_clk_src",
		   GCC_QUPV3_WRAP1_S4_CMD_RCGR, qup_se_150mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s5_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s5_clk_src",
		   GCC_QUPV3_WRAP1_S5_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s6_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s6_clk_src",
		   GCC_QUPV3_WRAP1_S6_CMD_RCGR, qup_se_100mhz);

/*
 * Branches -- one entry per gated QUP SE clock; combined ones point @rcg
 * at their own named RCG above.
 */
#define BRANCH_CLK(_name, _cbcr, _vote_reg, _vote_bit, _rcg)	\
	{								\
		.name = (_name),					\
		.regmap = &gcc_regmap,					\
		.cbcr_addr = (_cbcr),					\
		.clk_vote_addr = (_vote_reg),				\
		.vote_bit = (_vote_bit),					\
		.rcg = (_rcg),						\
	}

static const struct clk_branch_desc branches[] = {
	BRANCH_CLK("gcc_qupv3_wrap0_core_2x_clk", GCC_QUPV3_WRAP0_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap0_core_clk", GCC_QUPV3_WRAP0_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_m_ahb_clk", GCC_QUPV3_WRAP_0_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP_0_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_s_ahb_clk", GCC_QUPV3_WRAP_0_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP_0_S_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap0_s0_clk", GCC_QUPV3_WRAP0_S0_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S0_SHFT,
		   &gcc_qupv3_wrap0_s0_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s1_clk", GCC_QUPV3_WRAP0_S1_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S1_SHFT,
		   &gcc_qupv3_wrap0_s1_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s2_clk", GCC_QUPV3_WRAP0_S2_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S2_SHFT,
		   &gcc_qupv3_wrap0_s2_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s3_clk", GCC_QUPV3_WRAP0_S3_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S3_SHFT,
		   &gcc_qupv3_wrap0_s3_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s4_clk", GCC_QUPV3_WRAP0_S4_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S4_SHFT,
		   &gcc_qupv3_wrap0_s4_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s5_clk", GCC_QUPV3_WRAP0_S5_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP0_S5_SHFT,
		   &gcc_qupv3_wrap0_s5_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_core_2x_clk", GCC_QUPV3_WRAP1_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap1_core_clk", GCC_QUPV3_WRAP1_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_1_m_ahb_clk", GCC_QUPV3_WRAP_1_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_1_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_1_s_ahb_clk", GCC_QUPV3_WRAP_1_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_1_S_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap1_s0_clk", GCC_QUPV3_WRAP1_S0_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S0_SHFT,
		   &gcc_qupv3_wrap1_s0_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s1_clk", GCC_QUPV3_WRAP1_S1_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S1_SHFT,
		   &gcc_qupv3_wrap1_s1_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s2_clk", GCC_QUPV3_WRAP1_S2_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S2_SHFT,
		   &gcc_qupv3_wrap1_s2_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s3_clk", GCC_QUPV3_WRAP1_S3_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S3_SHFT,
		   &gcc_qupv3_wrap1_s3_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s4_clk", GCC_QUPV3_WRAP1_S4_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S4_SHFT,
		   &gcc_qupv3_wrap1_s4_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s5_clk", GCC_QUPV3_WRAP1_S5_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S5_SHFT,
		   &gcc_qupv3_wrap1_s5_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap1_s6_clk", GCC_QUPV3_WRAP1_S6_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_S6_SHFT,
		   &gcc_qupv3_wrap1_s6_clk_src),
};

static const struct clk_cfg cacao_clk_cfg = {
	.branches = branches,
	.n_branches = ARRAY_SIZE(branches),
	.pll_votes = pll_votes,
	.n_pll_votes = ARRAY_SIZE(pll_votes),
};

const struct clk_cfg *clk_get_cfg(void)
{
	return &cacao_clk_cfg;
}
