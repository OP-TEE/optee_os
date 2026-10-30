// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <mm/core_memprot.h>
#include <platform_config.h>
#include <util.h>

#include "clk_cfg.h"
#include "clock_group.h"
#include "rail_vote.h"

NORD_CLOCK_GROUP_REGISTER_GCC_PHYS_MEM();
NORD_CLOCK_GROUP_REGISTER_SE_GCC_PHYS_MEM();
NORD_CLOCK_GROUP_REGISTER_NE_GCC_PHYS_MEM();

#define SRC_BI_TCXO		0
#define SRC_SE_GPLL0		1
#define SRC_NE_GPLL0		2
#define SRC_GPLL0		3
#define SRC_GPLL0_EVEN		4

#define QUP_SE_DFS_STATES	8
#define QUP_SE_MND_WIDTH	16

static const struct clk_mux_config se_qup_se_120mhz[] = {
	{   7372800, SRC_SE_GPLL0, 2,  192, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  14745600, SRC_SE_GPLL0, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  19200000, SRC_BI_TCXO,  2,    0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  29491200, SRC_SE_GPLL0, 2,  768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  32000000, SRC_SE_GPLL0, 2,    4,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  48000000, SRC_SE_GPLL0, 2,    2,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  51200000, SRC_SE_GPLL0, 2,   32,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  64000000, SRC_SE_GPLL0, 2,    8,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  66666667, SRC_SE_GPLL0, 18,   0,     0, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  75000000, SRC_SE_GPLL0, 16,   0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_SE_GPLL0, 2,    2,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  96000000, SRC_SE_GPLL0, 2,    4,    25, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 100000000, SRC_SE_GPLL0, 12,   0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 102400000, SRC_SE_GPLL0, 2,   64,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 112000000, SRC_SE_GPLL0, 2,   14,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 117964800, SRC_SE_GPLL0, 2, 3072, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 120000000, SRC_SE_GPLL0, 10,   0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
};

static const struct clk_mux_config se_qup_se_100mhz[] = {
	{   7372800, SRC_SE_GPLL0, 2, 192, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  14745600, SRC_SE_GPLL0, 2, 384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  19200000, SRC_BI_TCXO,  2,   0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  29491200, SRC_SE_GPLL0, 2, 768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  32000000, SRC_SE_GPLL0, 2,   4,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  48000000, SRC_SE_GPLL0, 2,   2,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  51200000, SRC_SE_GPLL0, 2,  32,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  64000000, SRC_SE_GPLL0, 2,   8,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  66666667, SRC_SE_GPLL0, 18,  0,     0, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  75000000, SRC_SE_GPLL0, 16,  0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  80000000, SRC_SE_GPLL0, 2,   2,    15, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  96000000, SRC_SE_GPLL0, 2,   4,    25, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 100000000, SRC_SE_GPLL0, 12,  0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
};

static const struct clk_mux_config ne_qup_se_120mhz[] = {
	{   7372800, SRC_NE_GPLL0, 2,  192, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  14745600, SRC_NE_GPLL0, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  19200000, SRC_BI_TCXO,  2,    0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  29491200, SRC_NE_GPLL0, 2,  768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  32000000, SRC_NE_GPLL0, 2,    4,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  48000000, SRC_NE_GPLL0, 2,    2,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  51200000, SRC_NE_GPLL0, 2,   32,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  64000000, SRC_NE_GPLL0, 2,    8,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  66666667, SRC_NE_GPLL0, 18,   0,     0, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  75000000, SRC_NE_GPLL0, 16,   0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_NE_GPLL0, 2,    2,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  96000000, SRC_NE_GPLL0, 2,    4,    25, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 100000000, SRC_NE_GPLL0, 12,   0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 102400000, SRC_NE_GPLL0, 2,   64,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 112000000, SRC_NE_GPLL0, 2,   14,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 117964800, SRC_NE_GPLL0, 2, 3072, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 120000000, SRC_NE_GPLL0, 10,   0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
};

static const struct clk_mux_config ne_qup_se_100mhz[] = {
	{   7372800, SRC_NE_GPLL0, 2, 192, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  14745600, SRC_NE_GPLL0, 2, 384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  19200000, SRC_BI_TCXO,  2,   0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  29491200, SRC_NE_GPLL0, 2, 768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  32000000, SRC_NE_GPLL0, 2,   4,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  48000000, SRC_NE_GPLL0, 2,   2,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  51200000, SRC_NE_GPLL0, 2,  32,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  64000000, SRC_NE_GPLL0, 2,   8,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  66666667, SRC_NE_GPLL0, 18,  0,     0, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  75000000, SRC_NE_GPLL0, 16,  0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  80000000, SRC_NE_GPLL0, 2,   2,    15, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{  96000000, SRC_NE_GPLL0, 2,   4,    25, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 100000000, SRC_NE_GPLL0, 12,  0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
};

static const struct clk_mux_config qup_se_240mhz[] = {
	{   7372800, SRC_GPLL0_EVEN, 2,  384, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  14745600, SRC_GPLL0_EVEN, 2,  768, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  19200000, SRC_BI_TCXO,    2,    0,     0, 0x00,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  29491200, SRC_GPLL0_EVEN, 2, 1536, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  32000000, SRC_GPLL0_EVEN, 2,    8,    75, 0x01,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  48000000, SRC_GPLL0_EVEN, 2,    4,    25, 0x02,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  51200000, SRC_GPLL0_EVEN, 2,   64,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  64000000, SRC_GPLL0_EVEN, 2,   16,    75, 0x03,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  75000000, SRC_GPLL0_EVEN, 8,    0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  80000000, SRC_GPLL0_EVEN, 2,    4,    15, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{  96000000, SRC_GPLL0_EVEN, 2,    8,    25, 0x04,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_GPLL0,      12,   0,     0, 0x05,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 102400000, SRC_GPLL0_EVEN, 2,  128,   375, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 112000000, SRC_GPLL0_EVEN, 2,   28,    75, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 117964800, SRC_GPLL0_EVEN, 2, 6144, 15625, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 120000000, SRC_GPLL0,      10,   0,     0, 0x06,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 150000000, SRC_GPLL0_EVEN, 4,    0,     0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 240000000, SRC_GPLL0,      5,    0,     0, 0x07,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
};

static const struct clk_mux_config se_qup_wrap1_core_2x[] = {
	{  19200000, SRC_BI_TCXO,  2, 0, 0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 100000000, SRC_SE_GPLL0, 12, 0, 0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS },
	{ 150000000, SRC_SE_GPLL0,  8, 0, 0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_SVS_L1 },
	{ 200000000, SRC_SE_GPLL0,  6, 0, 0, CLK_DFS_NA,
	  RAIL_VOLTAGE_LEVEL_NOM },
};

static struct clk_regmap se_gcc_regmap = {
	.io.pa = SE_GCC_BASE,
	.size = SE_GCC_SIZE,
};

static struct clk_regmap ne_gcc_regmap = {
	.io.pa = NE_GCC_BASE,
	.size = NE_GCC_SIZE,
};

static struct clk_regmap gcc_regmap = {
	.io.pa = GCC_BASE,
	.size = GCC_SIZE,
};

static const struct clk_pll_vote pll_votes[] = {
	{ "xo", NULL, 0, 0 },
	{ "se_gpll0", &se_gcc_regmap, SE_GCC_PLL_BRANCH_ENA_VOTE,
	  PLL_VOTE_BIT_GPLL0 },
	{ "ne_gpll0", &ne_gcc_regmap, NE_GCC_PLL_BRANCH_ENA_VOTE,
	  PLL_VOTE_BIT_GPLL0 },
	{ "gpll0", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  PLL_VOTE_BIT_GPLL0 },
	{ "gpll0_div2", &gcc_regmap, GCC_PLL_BRANCH_ENA_VOTE,
	  PLL_VOTE_BIT_GPLL0 },
};

static const struct clk_parent_map parent_map_se[] = {
	{ SRC_BI_TCXO,  0 },
	{ SRC_SE_GPLL0, 1 },
};

static const struct clk_parent_map parent_map_ne[] = {
	{ SRC_BI_TCXO,  0 },
	{ SRC_NE_GPLL0, 1 },
};

static const struct clk_parent_map parent_map_gcc[] = {
	{ SRC_BI_TCXO,    0 },
	{ SRC_GPLL0,      1 },
	{ SRC_GPLL0_EVEN, 6 },
};

#define QUP_SE_RCG(_name, _regmap, _cmd_rcgr, _plan, _parents)	\
	{								\
		.name = (_name),					\
		.regmap = (_regmap),				\
		.cmd_rcgr_addr = (_cmd_rcgr),			\
		.mnd_width = QUP_SE_MND_WIDTH,			\
		.dfs_states = QUP_SE_DFS_STATES,			\
		.configs = (_plan),				\
		.n_configs = ARRAY_SIZE(_plan),			\
		.parent_map = (_parents),			\
		.n_parents = ARRAY_SIZE(_parents),		\
	}

static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s0_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s0_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S0_CMD_RCGR, se_qup_se_120mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s1_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s1_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S1_CMD_RCGR, se_qup_se_120mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s2_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s2_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S2_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s3_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s3_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S3_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s4_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s4_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S4_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s5_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s5_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S5_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap0_s6_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap0_s6_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S6_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);

static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s0_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s0_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S0_CMD_RCGR, se_qup_se_120mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s1_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s1_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S1_CMD_RCGR, se_qup_se_120mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s2_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s2_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S2_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s3_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s3_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S3_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s4_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s4_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S4_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s5_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s5_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S5_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);
static const struct clk_rcg_desc se_gcc_qupv3_wrap1_s6_clk_src =
	QUP_SE_RCG("se_gcc_qupv3_wrap1_s6_clk_src", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S6_CMD_RCGR, se_qup_se_100mhz,
		   parent_map_se);

static const struct clk_rcg_desc se_gcc_qupv3_wrap1_core_2x_clk_src = {
	.name = "se_gcc_qupv3_wrap1_core_2x_clk_src",
	.regmap = &se_gcc_regmap,
	.cmd_rcgr_addr = SE_GCC_QUPV3_WRAP1_CORE_2X_CMD_RCGR,
	.configs = se_qup_wrap1_core_2x,
	.n_configs = ARRAY_SIZE(se_qup_wrap1_core_2x),
	.parent_map = parent_map_se,
	.n_parents = ARRAY_SIZE(parent_map_se),
};

static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s0_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s0_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S0_CMD_RCGR, ne_qup_se_120mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s1_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s1_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S1_CMD_RCGR, ne_qup_se_120mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s2_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s2_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S2_CMD_RCGR, ne_qup_se_100mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s3_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s3_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S3_CMD_RCGR, ne_qup_se_100mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s4_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s4_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S4_CMD_RCGR, ne_qup_se_100mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s5_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s5_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S5_CMD_RCGR, ne_qup_se_100mhz,
		   parent_map_ne);
static const struct clk_rcg_desc ne_gcc_qupv3_wrap2_s6_clk_src =
	QUP_SE_RCG("ne_gcc_qupv3_wrap2_s6_clk_src", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S6_CMD_RCGR, ne_qup_se_100mhz,
		   parent_map_ne);

static const struct clk_rcg_desc gcc_qupv3_wrap3_s0_clk_src =
	QUP_SE_RCG("gcc_qupv3_wrap3_s0_clk_src", &gcc_regmap,
		   GCC_QUPV3_WRAP3_QSPI_REF_CMD_RCGR, qup_se_240mhz,
		   parent_map_gcc);

#define BRANCH_CLK(_name, _regmap, _cbcr, _vote_reg, _vote_bit, _rcg)	\
	{								\
		.name = (_name),					\
		.regmap = (_regmap),				\
		.cbcr_addr = (_cbcr),				\
		.clk_vote_addr = (_vote_reg),			\
		.vote_bit = (_vote_bit),				\
		.rcg = (_rcg),					\
	}

static const struct clk_branch_desc branches[] = {
	BRANCH_CLK("se_gcc_qupv3_wrap0_s0_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S0_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S0_SHFT, &se_gcc_qupv3_wrap0_s0_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s1_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S1_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S1_SHFT, &se_gcc_qupv3_wrap0_s1_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s2_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S2_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S2_SHFT, &se_gcc_qupv3_wrap0_s2_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s3_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S3_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S3_SHFT, &se_gcc_qupv3_wrap0_s3_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s4_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S4_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S4_SHFT, &se_gcc_qupv3_wrap0_s4_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s5_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S5_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S5_SHFT, &se_gcc_qupv3_wrap0_s5_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s6_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S6_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S6_SHFT, &se_gcc_qupv3_wrap0_s6_clk_src),

	BRANCH_CLK("se_gcc_qupv3_wrap1_s0_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S0_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S0_SHFT, &se_gcc_qupv3_wrap1_s0_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s1_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S1_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S1_SHFT, &se_gcc_qupv3_wrap1_s1_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s2_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S2_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S2_SHFT, &se_gcc_qupv3_wrap1_s2_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s3_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S3_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S3_SHFT, &se_gcc_qupv3_wrap1_s3_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s4_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S4_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S4_SHFT, &se_gcc_qupv3_wrap1_s4_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s5_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S5_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   SE_QUPV3_WRAP1_S5_SHFT, &se_gcc_qupv3_wrap1_s5_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s6_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S6_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   SE_QUPV3_WRAP1_S6_SHFT, &se_gcc_qupv3_wrap1_s6_clk_src),

	BRANCH_CLK("ne_gcc_qupv3_wrap2_s0_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S0_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S0_SHFT, &ne_gcc_qupv3_wrap2_s0_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s1_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S1_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S1_SHFT, &ne_gcc_qupv3_wrap2_s1_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s2_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S2_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S2_SHFT, &ne_gcc_qupv3_wrap2_s2_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s3_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S3_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S3_SHFT, &ne_gcc_qupv3_wrap2_s3_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s4_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S4_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S4_SHFT, &ne_gcc_qupv3_wrap2_s4_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s5_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S5_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S5_SHFT, &ne_gcc_qupv3_wrap2_s5_clk_src),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s6_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S6_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_S6_SHFT, &ne_gcc_qupv3_wrap2_s6_clk_src),

	BRANCH_CLK("gcc_qupv3_wrap3_s0_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_S0_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE,
		   QUPV3_WRAP3_S0_SHFT, &gcc_qupv3_wrap3_s0_clk_src),

	BRANCH_CLK("se_gcc_qupv3_wrap0_core_2x_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_CORE_2X_CBCR,
		   SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_CORE_2X_SHFT, NULL),
	BRANCH_CLK("se_gcc_qupv3_wrap0_core_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_CORE_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_CORE_SHFT, NULL),
	BRANCH_CLK("se_gcc_qupv3_wrap0_m_ahb_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_M_AHB_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_M_AHB_SHFT, NULL),
	BRANCH_CLK("se_gcc_qupv3_wrap0_s_ahb_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP0_S_AHB_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP0_S_AHB_SHFT, NULL),

	BRANCH_CLK("se_gcc_qupv3_wrap1_core_2x_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_CORE_2X_CBCR,
		   SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_CORE_2X_SHFT,
		   &se_gcc_qupv3_wrap1_core_2x_clk_src),
	BRANCH_CLK("se_gcc_qupv3_wrap1_core_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_CORE_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_CORE_SHFT, NULL),
	BRANCH_CLK("se_gcc_qupv3_wrap1_m_ahb_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_M_AHB_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_M_AHB_SHFT, NULL),
	BRANCH_CLK("se_gcc_qupv3_wrap1_s_ahb_clk", &se_gcc_regmap,
		   SE_GCC_QUPV3_WRAP1_S_AHB_CBCR, SE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   SE_QUPV3_WRAP1_S_AHB_SHFT, NULL),

	BRANCH_CLK("ne_gcc_qupv3_wrap2_core_2x_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_CORE_2X_CBCR,
		   NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_CORE_2X_SHFT, NULL),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_core_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_CORE_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE_1,
		   NE_QUPV3_WRAP2_CORE_SHFT, NULL),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_m_ahb_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_M_AHB_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   NE_QUPV3_WRAP2_M_AHB_SHFT, NULL),
	BRANCH_CLK("ne_gcc_qupv3_wrap2_s_ahb_clk", &ne_gcc_regmap,
		   NE_GCC_QUPV3_WRAP2_S_AHB_CBCR, NE_GCC_CLOCK_BRANCH_ENA_VOTE,
		   NE_QUPV3_WRAP2_S_AHB_SHFT, NULL),

	BRANCH_CLK("gcc_qupv3_wrap3_core_2x_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_CORE_2X_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE,
		   QUPV3_WRAP3_CORE_2X_SHFT, NULL),
	BRANCH_CLK("gcc_qupv3_wrap3_core_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_CORE_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE,
		   QUPV3_WRAP3_CORE_SHFT, NULL),
	BRANCH_CLK("gcc_qupv3_wrap3_m_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_M_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE,
		   QUPV3_WRAP3_M_SHFT, NULL),
	BRANCH_CLK("gcc_qupv3_wrap3_s_ahb_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_S_AHB_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE_2,
		   QUPV3_WRAP3_S_AHB_SHFT, NULL),
	BRANCH_CLK("gcc_qupv3_wrap3_qspi_ref_clk", &gcc_regmap,
		   GCC_QUPV3_WRAP3_QSPI_REF_CBCR, GCC_CLOCK_BRANCH_ENA_VOTE,
		   QUPV3_WRAP3_QSPI_REF_SHFT, NULL),
};

static const struct clk_cfg nord_clk_cfg = {
	.branches = branches,
	.n_branches = ARRAY_SIZE(branches),
	.pll_votes = pll_votes,
	.n_pll_votes = ARRAY_SIZE(pll_votes),
};

const struct clk_cfg *clk_get_cfg(void)
{
	return &nord_clk_cfg;
}
