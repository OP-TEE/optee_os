// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QTI ICB (Interconnect Bus) driver - Nord target data.
 */

#include "icbuarbi.h"

/* HW NODE DECLARATIONS */
/* ACV */
static struct icb_hw_request bcm_acv_requests[1];
static struct icb_hw_node bcm_acv = {
	NULL, /**< node linkage */
	"ACV", /**< name */
	ICB_HW_NODE_KIND_VECTOR, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_acv_requests}, /**< request_list */
	0x0, /**< output */
};

/* CE0 */
static struct icb_hw_request bcm_ce0_requests[1];
static struct icb_hw_node bcm_ce0 = {
	NULL, /**< node linkage */
	"CE0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_ce0_requests}, /**< request_list */
	0, /**< output */
};

/* CE1 */
static struct icb_hw_request bcm_ce1_requests[1];
static struct icb_hw_node bcm_ce1 = {
	NULL, /**< node linkage */
	"CE1", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_ce1_requests}, /**< request_list */
	0, /**< output */
};

/* CE2 */
static struct icb_hw_request bcm_ce2_requests[1];
static struct icb_hw_node bcm_ce2 = {
	NULL, /**< node linkage */
	"CE2", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_ce2_requests}, /**< request_list */
	0, /**< output */
};

/* CN0 */
static struct icb_hw_request bcm_cn0_requests[2];
static struct icb_hw_node bcm_cn0 = {
	NULL, /**< node linkage */
	"CN0", /**< name */
	ICB_HW_NODE_KIND_VECTOR, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 2, bcm_cn0_requests}, /**< request_list */
	0x1, /**< output */
};

/* MC0 */
static struct icb_hw_request bcm_mc0_requests[1];
static struct icb_hw_node bcm_mc0 = {
	NULL, /**< node linkage */
	"MC0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_mc0_requests}, /**< request_list */
	0, /**< output */
};

/* SH0 */
static struct icb_hw_request bcm_sh0_requests[1];
static struct icb_hw_node bcm_sh0 = {
	NULL, /**< node linkage */
	"SH0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_sh0_requests}, /**< request_list */
	0, /**< output */
};

/* SH1 */
static struct icb_hw_request bcm_sh1_requests[3];
static struct icb_hw_node bcm_sh1 = {
	NULL, /**< node linkage */
	"SH1", /**< name */
	ICB_HW_NODE_KIND_VECTOR, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 3, bcm_sh1_requests}, /**< request_list */
	0x1, /**< output */
};

/* SN1 */
static struct icb_hw_request bcm_sn1_requests[1];
static struct icb_hw_node bcm_sn1 = {
	NULL, /**< node linkage */
	"SN1", /**< name */
	ICB_HW_NODE_KIND_VECTOR, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_sn1_requests}, /**< request_list */
	0x1, /**< output */
};

/* MASTER DECLARATIONS */
/* CHM_APPS */
static struct icb_hw_node *master_chm_apps_hw_nodes[] = {
	&bcm_sh1,
};

static struct icb_master master_chm_apps = {
	ICBID_MASTER_APPSS_PROC,
	32, /**< width */
	6, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_chm_apps_hw_nodes, /**< hw nodes */
};

/* LLCC_MC */
static struct icb_master master_llcc_mc = {
	ICBID_MASTER_LLCC,
	4, /**< width */
	16, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QNM_AGGRE_NORTH */
static struct icb_hw_node *master_qnm_aggre_north_hw_nodes[] = {
	&bcm_sh1,
};

static struct icb_master master_qnm_aggre_north = {
	ICBID_MASTER_A1NOC_TILE_HSCNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qnm_aggre_north_hw_nodes, /**< hw nodes */
};

/* QNM_HSCNOC */
static struct icb_hw_node *master_qnm_hscnoc_hw_nodes[] = {
	&bcm_cn0,
};

static struct icb_master master_qnm_hscnoc = {
	ICBID_MASTER_HSCNOC_CNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qnm_hscnoc_hw_nodes, /**< hw nodes */
};

/* QSM_CFG */
static struct icb_hw_node *master_qsm_cfg_hw_nodes[] = {
	&bcm_cn0,
};

static struct icb_master master_qsm_cfg = {
	ICBID_MASTER_CNOC_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qsm_cfg_hw_nodes, /**< hw nodes */
};

/* QXM_CRYPTO_0 */
static struct icb_hw_node *master_qxm_crypto_0_hw_nodes[] = {
	&bcm_ce0,
};

static struct icb_master master_qxm_crypto_0 = {
	ICBID_MASTER_CRYPTO_CORE0,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qxm_crypto_0_hw_nodes, /**< hw nodes */
};

/* QXM_CRYPTO_1 */
static struct icb_hw_node *master_qxm_crypto_1_hw_nodes[] = {
	&bcm_ce1,
};

static struct icb_master master_qxm_crypto_1 = {
	ICBID_MASTER_CRYPTO_CORE1,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qxm_crypto_1_hw_nodes, /**< hw nodes */
};

/* QXM_CRYPTO_2 */
static struct icb_hw_node *master_qxm_crypto_2_hw_nodes[] = {
	&bcm_ce2,
};

static struct icb_master master_qxm_crypto_2 = {
	ICBID_MASTER_CRYPTO_CORE2,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qxm_crypto_2_hw_nodes, /**< hw nodes */
};

/* SLAVE DECLARATIONS */
/* EBI */
static struct icb_hw_node *slave_ebi_hw_nodes[] = {
	&bcm_mc0,
	&bcm_acv,
};

static struct icb_slave slave_ebi = {
	ICBID_SLAVE_EBI1,
	4, /**< width */
	16, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	2, /**< number of hw_nodes */
	slave_ebi_hw_nodes, /**< hw nodes */
};

/* QHS_CRYPTO0_CFG */
static struct icb_slave slave_qhs_crypto0_cfg = {
	ICBID_SLAVE_CRYPTO_0_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHS_CRYPTO1_CFG */
static struct icb_slave slave_qhs_crypto1_cfg = {
	ICBID_SLAVE_CRYPTO_1_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHS_CRYPTO2_CFG */
static struct icb_slave slave_qhs_crypto2_cfg = {
	ICBID_SLAVE_CRYPTO_2_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHS_PRNG */
static struct icb_slave slave_qhs_prng = {
	ICBID_SLAVE_PRNG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QNS_A1NOC_HSCNOC */
static struct icb_hw_node *slave_qns_a1noc_hscnoc_hw_nodes[] = {
	&bcm_sn1,
};

static struct icb_slave slave_qns_a1noc_hscnoc = {
	ICBID_SLAVE_A1NOC_HSCNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_a1noc_hscnoc_hw_nodes, /**< hw nodes */
};

/* QNS_HSCNOC_CNOC */
static struct icb_hw_node *slave_qns_hscnoc_cnoc_hw_nodes[] = {
	&bcm_sh1,
};

static struct icb_slave slave_qns_hscnoc_cnoc = {
	ICBID_SLAVE_HSCNOC_CNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_hscnoc_cnoc_hw_nodes, /**< hw nodes */
};

/* QNS_LLCC */
static struct icb_hw_node *slave_qns_llcc_hw_nodes[] = {
	&bcm_sh0,
};

static struct icb_slave slave_qns_llcc = {
	ICBID_SLAVE_LLCC,
	16, /**< width */
	16, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_llcc_hw_nodes, /**< hw nodes */
};

/* QSS_CFG */
static struct icb_slave slave_qss_cfg = {
	ICBID_SLAVE_CNOC_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* TOPOLOGY ROUTE DECLARATIONS */
static struct icb_pair route_chm_apps_ebi_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_llcc
	},
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_chm_apps_ebi = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_EBI1,
	2,
	route_chm_apps_ebi_hops
};

static struct icb_pair route_chm_apps_qhs_crypto0_cfg_hops[3] = {
	{
		&master_chm_apps,
		&slave_qns_hscnoc_cnoc
	},
	{
		&master_qnm_hscnoc,
		&slave_qss_cfg
	},
	{
		&master_qsm_cfg,
		&slave_qhs_crypto0_cfg
	},
};

static struct icb_route route_chm_apps_qhs_crypto0_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_CRYPTO_0_CFG,
	3,
	route_chm_apps_qhs_crypto0_cfg_hops
};

static struct icb_pair route_chm_apps_qhs_crypto1_cfg_hops[3] = {
	{
		&master_chm_apps,
		&slave_qns_hscnoc_cnoc
	},
	{
		&master_qnm_hscnoc,
		&slave_qss_cfg
	},
	{
		&master_qsm_cfg,
		&slave_qhs_crypto1_cfg
	},
};

static struct icb_route route_chm_apps_qhs_crypto1_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_CRYPTO_1_CFG,
	3,
	route_chm_apps_qhs_crypto1_cfg_hops
};

static struct icb_pair route_chm_apps_qhs_crypto2_cfg_hops[3] = {
	{
		&master_chm_apps,
		&slave_qns_hscnoc_cnoc
	},
	{
		&master_qnm_hscnoc,
		&slave_qss_cfg
	},
	{
		&master_qsm_cfg,
		&slave_qhs_crypto2_cfg
	},
};

static struct icb_route route_chm_apps_qhs_crypto2_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_CRYPTO_2_CFG,
	3,
	route_chm_apps_qhs_crypto2_cfg_hops
};

static struct icb_pair route_chm_apps_qhs_prng_hops[3] = {
	{
		&master_chm_apps,
		&slave_qns_hscnoc_cnoc
	},
	{
		&master_qnm_hscnoc,
		&slave_qss_cfg
	},
	{
		&master_qsm_cfg,
		&slave_qhs_prng
	},
};

static struct icb_route route_chm_apps_qhs_prng = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_PRNG,
	3,
	route_chm_apps_qhs_prng_hops
};

static struct icb_pair route_qxm_crypto_0_ebi_hops[3] = {
	{
		&master_qxm_crypto_0,
		&slave_qns_a1noc_hscnoc
	},
	{
		&master_qnm_aggre_north,
		&slave_qns_llcc
	},
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_qxm_crypto_0_ebi = {
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_SLAVE_EBI1,
	3,
	route_qxm_crypto_0_ebi_hops
};

static struct icb_pair route_qxm_crypto_1_ebi_hops[3] = {
	{
		&master_qxm_crypto_1,
		&slave_qns_a1noc_hscnoc
	},
	{
		&master_qnm_aggre_north,
		&slave_qns_llcc
	},
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_qxm_crypto_1_ebi = {
	ICBID_MASTER_CRYPTO_CORE1,
	ICBID_SLAVE_EBI1,
	3,
	route_qxm_crypto_1_ebi_hops
};

static struct icb_pair route_qxm_crypto_2_ebi_hops[3] = {
	{
		&master_qxm_crypto_2,
		&slave_qns_a1noc_hscnoc
	},
	{
		&master_qnm_aggre_north,
		&slave_qns_llcc
	},
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_qxm_crypto_2_ebi = {
	ICBID_MASTER_CRYPTO_CORE2,
	ICBID_SLAVE_EBI1,
	3,
	route_qxm_crypto_2_ebi_hops
};

/* NODE AND ROUTE LISTS */
static struct icb_route *icb_route_list[8] = {
	&route_chm_apps_ebi,
	&route_chm_apps_qhs_crypto0_cfg,
	&route_chm_apps_qhs_crypto1_cfg,
	&route_chm_apps_qhs_crypto2_cfg,
	&route_chm_apps_qhs_prng,
	&route_qxm_crypto_0_ebi,
	&route_qxm_crypto_1_ebi,
	&route_qxm_crypto_2_ebi,
};

static struct icb_master *icb_master_list[8] = {
	&master_chm_apps,
	&master_llcc_mc,
	&master_qnm_aggre_north,
	&master_qnm_hscnoc,
	&master_qsm_cfg,
	&master_qxm_crypto_0,
	&master_qxm_crypto_1,
	&master_qxm_crypto_2,
};

static struct icb_slave *icb_slave_list[9] = {
	&slave_ebi,
	&slave_qhs_crypto0_cfg,
	&slave_qhs_crypto1_cfg,
	&slave_qhs_crypto2_cfg,
	&slave_qhs_prng,
	&slave_qns_a1noc_hscnoc,
	&slave_qns_hscnoc_cnoc,
	&slave_qns_llcc,
	&slave_qss_cfg,
};

static struct icb_hw_node *icb_hw_node_list[9] = {
	&bcm_acv,
	&bcm_ce0,
	&bcm_ce1,
	&bcm_ce2,
	&bcm_cn0,
	&bcm_mc0,
	&bcm_sh0,
	&bcm_sh1,
	&bcm_sn1,
};

/* EXTERNAL DATA DECLARATIONS */
struct icb_info info = {
	8, /**< number of routes */
	icb_route_list, /**< routes */
	8, /**< number of masters */
	icb_master_list, /**< masters */
	9, /**< number of slaves */
	icb_slave_list, /**< slaves */
	9, /**< number of hw_nodes */
	icb_hw_node_list, /**< hw_nodes */
};
