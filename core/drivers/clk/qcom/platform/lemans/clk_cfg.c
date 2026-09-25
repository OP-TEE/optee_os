// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <platform_config.h>
#include <util.h>

#include "clk_cfg.h"
#include "clock_group.h"
#include "rail_vote.h"

/* Software source identities, indexing pll_votes[]. */
#define SRC_BI_TCXO			0
#define SRC_GPLL0_OUT_EVEN		1
#define SRC_GPLL4_OUT_MAIN		2

#define QUP_SE_DFS_STATES	8

static const struct clk_mux_config qup_se_120mhz[] = {
	{   7372800, SRC_GPLL0_OUT_EVEN, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  14745600, SRC_GPLL0_OUT_EVEN, 2,  768, 15625, 0x00,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  19200000, SRC_BI_TCXO,        2,    0,     0, 0x01,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  29491200, SRC_GPLL0_OUT_EVEN, 2, 1536, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  32000000, SRC_GPLL0_OUT_EVEN, 2,    8,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  48000000, SRC_GPLL0_OUT_EVEN, 2,    4,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  51200000, SRC_GPLL0_OUT_EVEN, 2,   64,   375, 0x03,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  64000000, SRC_GPLL0_OUT_EVEN, 2,   16,    75, 0x04,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  75000000, SRC_GPLL0_OUT_EVEN, 8,    0,     0, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_GPLL0_OUT_EVEN, 2,    4,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  96000000, SRC_GPLL0_OUT_EVEN, 2,    8,    25, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_GPLL0_OUT_EVEN, 6,    0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 120000000, SRC_GPLL0_OUT_EVEN, 5,    0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS },
};

static const struct clk_mux_config qup_se_100mhz[] = {
	{   7372800, SRC_GPLL0_OUT_EVEN, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  14745600, SRC_GPLL0_OUT_EVEN, 2,  768, 15625, 0x00,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  19200000, SRC_BI_TCXO,        2,    0,     0, 0x01,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  29491200, SRC_GPLL0_OUT_EVEN, 2, 1536, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  32000000, SRC_GPLL0_OUT_EVEN, 2,    8,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  48000000, SRC_GPLL0_OUT_EVEN, 2,    4,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  51200000, SRC_GPLL0_OUT_EVEN, 2,   64,   375, 0x03,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  64000000, SRC_GPLL0_OUT_EVEN, 2,   16,    75, 0x04,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  75000000, SRC_GPLL0_OUT_EVEN, 8,    0,     0, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_GPLL0_OUT_EVEN, 2,    4,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  96000000, SRC_GPLL0_OUT_EVEN, 2,    8,    25, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_GPLL0_OUT_EVEN, 6,    0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS },
};

static const struct clk_mux_config qup_se_403mhz[] = {
	{   7372800, SRC_GPLL0_OUT_EVEN, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  14745600, SRC_GPLL0_OUT_EVEN, 2,  768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  19200000, SRC_BI_TCXO,        2,    0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  29491200, SRC_GPLL0_OUT_EVEN, 2, 1536, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  32000000, SRC_GPLL0_OUT_EVEN, 2,    8,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  48000000, SRC_GPLL0_OUT_EVEN, 2,    4,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_MIN_SVS },
	{  64000000, SRC_GPLL0_OUT_EVEN, 2,   16,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_LOW_SVS },
	{  75000000, SRC_GPLL0_OUT_EVEN, 8,    0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_GPLL0_OUT_EVEN, 2,    4,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  96000000, SRC_GPLL0_OUT_EVEN, 2,    8,    25, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_GPLL0_OUT_EVEN, 6,    0,     0, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 403200000, SRC_GPLL4_OUT_MAIN, 4,    0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS },
};

static struct clk_regmap gcc_regmap = {
	.io.pa = GCC_BASE,
	.size = GCC_SIZE,
};

static const struct clk_pll_vote pll_votes[] = {
	{ "xo", NULL, 0, 0 },
	{ "gpll0_div2", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL0 },
	{ "gpll4", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  GCC_PLL_VOTE_BIT_GPLL4 },
};

/*
 * mux_sel values are this wrapper's own SRC_SEL encoding -- literal, not
 * shared macros, since a differently-wired RCG would need different
 * values for the same PLL.
 */
static const struct clk_parent_map parent_map_0[] = {
	{ SRC_BI_TCXO,        0 },	/* BI_TCXO */
	{ SRC_GPLL0_OUT_EVEN, 6 },	/* GPLL0_OUT_EVEN */
	{ SRC_GPLL4_OUT_MAIN, 5 },	/* GPLL4_OUT_MAIN */
};

/* RCGs -- one named instance per QUP SE index that needs rate control. */
#define QUP_SE_MND_WIDTH	16

#define QUP_SE_RCG(_name, _cmd_rcgr, _plan)				\
	{								\
		.name = (_name),					\
		.regmap = &gcc_regmap,					\
		.cmd_rcgr_addr = (_cmd_rcgr),				\
		.mnd_width = QUP_SE_MND_WIDTH,				\
		.dfs_states = QUP_SE_DFS_STATES,			\
		.configs = (_plan),					\
		.n_configs = ARRAY_SIZE(_plan),			\
		.parent_map = parent_map_0,				\
		.n_parents = ARRAY_SIZE(parent_map_0),			\
	}

static const struct clk_rcg_desc gcc_qupv3_wrap0_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s0_clk_src",
		   GCC_QUPV3_WRAP0_S0_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s1_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s1_clk_src",
		   GCC_QUPV3_WRAP0_S1_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s2_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s2_clk_src",
		   GCC_QUPV3_WRAP0_S2_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s3_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s3_clk_src",
		   GCC_QUPV3_WRAP0_S3_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s4_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s4_clk_src",
		   GCC_QUPV3_WRAP0_S4_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s5_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s5_clk_src",
		   GCC_QUPV3_WRAP0_S5_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap0_s6_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap0_s6_clk_src",
		   GCC_QUPV3_WRAP0_S6_CMD_RCGR, qup_se_100mhz);

static const struct clk_rcg_desc gcc_qupv3_wrap1_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s0_clk_src",
		   GCC_QUPV3_WRAP1_S0_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s1_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s1_clk_src",
		   GCC_QUPV3_WRAP1_S1_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s2_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s2_clk_src",
		   GCC_QUPV3_WRAP1_S2_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s3_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s3_clk_src",
		   GCC_QUPV3_WRAP1_S3_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s4_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s4_clk_src",
		   GCC_QUPV3_WRAP1_S4_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s5_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s5_clk_src",
		   GCC_QUPV3_WRAP1_S5_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap1_s6_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap1_s6_clk_src",
		   GCC_QUPV3_WRAP1_S6_CMD_RCGR, qup_se_100mhz);

static const struct clk_rcg_desc gcc_qupv3_wrap2_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s0_clk_src",
		   GCC_QUPV3_WRAP2_S0_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s1_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s1_clk_src",
		   GCC_QUPV3_WRAP2_S1_CMD_RCGR, qup_se_120mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s2_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s2_clk_src",
		   GCC_QUPV3_WRAP2_S2_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s3_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s3_clk_src",
		   GCC_QUPV3_WRAP2_S3_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s4_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s4_clk_src",
		   GCC_QUPV3_WRAP2_S4_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s5_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s5_clk_src",
		   GCC_QUPV3_WRAP2_S5_CMD_RCGR, qup_se_100mhz);
static const struct clk_rcg_desc gcc_qupv3_wrap2_s6_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap2_s6_clk_src",
		   GCC_QUPV3_WRAP2_S6_CMD_RCGR, qup_se_100mhz);

static const struct clk_rcg_desc gcc_qupv3_wrap3_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap3_s0_clk_src",
		   GCC_QUPV3_WRAP3_S0_CMD_RCGR, qup_se_403mhz);

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
		.vote_bit = (_vote_bit),				\
		.rcg = (_rcg),						\
	}

static const struct clk_branch_desc branches[] = {
	BRANCH_CLK("gcc_qupv3_wrap0_s0_clk", GCC_QUPV3_WRAP0_S0_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S0_SHFT,
		   &gcc_qupv3_wrap0_s0_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s1_clk", GCC_QUPV3_WRAP0_S1_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S1_SHFT,
		   &gcc_qupv3_wrap0_s1_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s2_clk", GCC_QUPV3_WRAP0_S2_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S2_SHFT,
		   &gcc_qupv3_wrap0_s2_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s3_clk", GCC_QUPV3_WRAP0_S3_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S3_SHFT,
		   &gcc_qupv3_wrap0_s3_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s4_clk", GCC_QUPV3_WRAP0_S4_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S4_SHFT,
		   &gcc_qupv3_wrap0_s4_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s5_clk", GCC_QUPV3_WRAP0_S5_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S5_SHFT,
		   &gcc_qupv3_wrap0_s5_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap0_s6_clk", GCC_QUPV3_WRAP0_S6_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_S6_SHFT,
		   &gcc_qupv3_wrap0_s6_clk_src),

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
		   GCC_CLOCK_BRANCH_ENA_VOTE_3, QUPV3_WRAP1_S6_SHFT,
		   &gcc_qupv3_wrap1_s6_clk_src),

	BRANCH_CLK("gcc_qupv3_wrap2_s0_clk", GCC_QUPV3_WRAP2_S0_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S0_SHFT,
		   &gcc_qupv3_wrap2_s0_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s1_clk", GCC_QUPV3_WRAP2_S1_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S1_SHFT,
		   &gcc_qupv3_wrap2_s1_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s2_clk", GCC_QUPV3_WRAP2_S2_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S2_SHFT,
		   &gcc_qupv3_wrap2_s2_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s3_clk", GCC_QUPV3_WRAP2_S3_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S3_SHFT,
		   &gcc_qupv3_wrap2_s3_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s4_clk", GCC_QUPV3_WRAP2_S4_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S4_SHFT,
		   &gcc_qupv3_wrap2_s4_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s5_clk", GCC_QUPV3_WRAP2_S5_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_S5_SHFT,
		   &gcc_qupv3_wrap2_s5_clk_src),
	BRANCH_CLK("gcc_qupv3_wrap2_s6_clk", GCC_QUPV3_WRAP2_S6_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_3, QUPV3_WRAP2_S6_SHFT,
		   &gcc_qupv3_wrap2_s6_clk_src),

	BRANCH_CLK("gcc_qupv3_wrap3_s0_clk", GCC_QUPV3_WRAP3_S0_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE, QUPV3_WRAP3_S0_SHFT,
		   &gcc_qupv3_wrap3_s0_clk_src),

	BRANCH_CLK("gcc_qupv3_wrap0_core_2x_clk",
		   GCC_QUPV3_WRAP0_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap0_core_clk",
		   GCC_QUPV3_WRAP0_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP0_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_m_ahb_clk",
		   GCC_QUPV3_WRAP_0_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_0_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_0_s_ahb_clk",
		   GCC_QUPV3_WRAP_0_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_0_S_AHB_SHFT,
		   NULL),

	BRANCH_CLK("gcc_qupv3_wrap1_core_2x_clk",
		   GCC_QUPV3_WRAP1_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap1_core_clk",
		   GCC_QUPV3_WRAP1_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP1_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_1_m_ahb_clk",
		   GCC_QUPV3_WRAP_1_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_1_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_1_s_ahb_clk",
		   GCC_QUPV3_WRAP_1_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_1, QUPV3_WRAP_1_S_AHB_SHFT,
		   NULL),

	BRANCH_CLK("gcc_qupv3_wrap2_core_2x_clk",
		   GCC_QUPV3_WRAP2_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap2_core_clk",
		   GCC_QUPV3_WRAP2_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP2_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_2_m_ahb_clk",
		   GCC_QUPV3_WRAP_2_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP_2_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_2_s_ahb_clk",
		   GCC_QUPV3_WRAP_2_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE_2, QUPV3_WRAP_2_S_AHB_SHFT,
		   NULL),

	BRANCH_CLK("gcc_qupv3_wrap3_core_2x_clk",
		   GCC_QUPV3_WRAP3_CORE_2X_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE, QUPV3_WRAP3_CORE_2X_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap3_core_clk",
		   GCC_QUPV3_WRAP3_CORE_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE, QUPV3_WRAP3_CORE_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_3_m_ahb_clk",
		   GCC_QUPV3_WRAP_3_M_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE, QUPV3_WRAP_3_M_AHB_SHFT,
		   NULL),
	BRANCH_CLK("gcc_qupv3_wrap_3_s_ahb_clk",
		   GCC_QUPV3_WRAP_3_S_AHB_CBCR,
		   GCC_CLOCK_BRANCH_ENA_VOTE, QUPV3_WRAP_3_S_AHB_SHFT,
		   NULL),
};

static const struct clk_cfg lemans_clk_cfg = {
	.branches = branches,
	.n_branches = ARRAY_SIZE(branches),
	.pll_votes = pll_votes,
	.n_pll_votes = ARRAY_SIZE(pll_votes),
};

const struct clk_cfg *clk_get_cfg(void)
{
	return &lemans_clk_cfg;
}
