// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QTI ICB (Interconnect Bus) driver - Lemans target data.
 *
 * Trimmed to the routes with an in-tree consumer: the GENI SPI driver
 * (#8042, dTPM on QUP2 SE2) and the GPCE crypto engine (#8194, SHA-1 hash,
 * CRYPTO_CORE0/1 to DDR/LLCC). The full BCM/route catalog for Lemans also
 * carried PKA/HWKM/IPA and the other three QUP cores with no landing
 * consumer; add those back alongside their consumers.
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
	0, /**< output */
};

/* CE0 */
static struct icb_hw_request bcm_ce0_requests[2];
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
	{0, 2, bcm_ce0_requests}, /**< request_list */
	0, /**< output */
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

/* QUP2 */
static struct icb_hw_request bcm_qup2_requests[2];
static struct icb_hw_node bcm_qup2 = {
	NULL, /**< node linkage */
	"QUP2", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 2, bcm_qup2_requests}, /**< request_list */
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

/* SN0 */
static struct icb_hw_request bcm_sn0_requests[1];
static struct icb_hw_node bcm_sn0 = {
	NULL, /**< node linkage */
	"SN0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_sn0_requests}, /**< request_list */
	0, /**< output */
};

/* SN4 */
static struct icb_hw_request bcm_sn4_requests[2];
static struct icb_hw_node bcm_sn4 = {
	NULL, /**< node linkage */
	"SN4", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 2, bcm_sn4_requests}, /**< request_list */
	0, /**< output */
};

/* MASTER DECLARATIONS */
/* LLCC_MC */
static struct icb_master master_llcc_mc = {
	ICBID_MASTER_LLCC,
	4, /**< width */
	8, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* AGGRE2_NOC_MASTER */
static struct icb_hw_node *master_qnm_aggre2_noc_hw_nodes[] = {
	&bcm_sn4,
};

static struct icb_master master_qnm_aggre2_noc = {
	ICBID_MASTER_A2NOC_SNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qnm_aggre2_noc_hw_nodes, /**< hw nodes */
};

/* SNOC_SF_MEM_NOC_MASTER */
static struct icb_master master_qnm_snoc_sf = {
	ICBID_MASTER_SNOC_SF_MEM_NOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QUP2_CORE_MASTER */
static struct icb_master master_qup2_core_master = {
	ICBID_MASTER_QUP_CORE_2,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* CRYPTO_CORE0_MASTER */
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

/* CRYPTO_CORE1_MASTER */
static struct icb_hw_node *master_qxm_crypto_1_hw_nodes[] = {
	&bcm_ce0,
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

/* SLAVE DECLARATIONS */
/* EBI */
static struct icb_hw_node *slave_ebi_hw_nodes[] = {
	&bcm_mc0,
	&bcm_acv,
};

static struct icb_slave slave_ebi = {
	ICBID_SLAVE_EBI1,
	4, /**< width */
	8, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	2, /**< number of hw_nodes */
	slave_ebi_hw_nodes, /**< hw nodes */
};

/* A2NOC_SNOC_SLAVE */
static struct icb_hw_node *slave_qns_a2noc_snoc_hw_nodes[] = {
	&bcm_sn4,
};

static struct icb_slave slave_qns_a2noc_snoc = {
	ICBID_SLAVE_A2NOC_SNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_a2noc_snoc_hw_nodes, /**< hw nodes */
};

/* SNOC_GEM_NOC_SF_SLAVE */
static struct icb_hw_node *slave_qns_gemnoc_sf_hw_nodes[] = {
	&bcm_sn0,
};

static struct icb_slave slave_qns_gemnoc_sf = {
	ICBID_SLAVE_SNOC_GEM_NOC_SF,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_gemnoc_sf_hw_nodes, /**< hw nodes */
};

/* LLCC_SLAVE */
static struct icb_hw_node *slave_qns_llcc_hw_nodes[] = {
	&bcm_sh0,
};

static struct icb_slave slave_qns_llcc = {
	ICBID_SLAVE_LLCC,
	16, /**< width */
	6, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_llcc_hw_nodes, /**< hw nodes */
};

/* QUP2_CORE_SLAVE */
static struct icb_hw_node *slave_qup2_core_slave_hw_nodes[] = {
	&bcm_qup2,
};

static struct icb_slave slave_qup2_core_slave = {
	ICBID_SLAVE_QUP_CORE_2,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qup2_core_slave_hw_nodes, /**< hw nodes */
};

/* ROUTE DECLARATIONS */
static struct icb_pair route_qup2_core_master_qup2_core_slave_hops[1] = {
	{
		&master_qup2_core_master,
		&slave_qup2_core_slave
	},
};

static struct icb_route route_qup2_core_master_qup2_core_slave = {
	ICBID_MASTER_QUP_CORE_2,
	ICBID_SLAVE_QUP_CORE_2,
	1,
	route_qup2_core_master_qup2_core_slave_hops
};

static struct icb_pair route_qxm_crypto_0_ebi_hops[4] = {
	{
		&master_qxm_crypto_0,
		&slave_qns_a2noc_snoc
	},
	{
		&master_qnm_aggre2_noc,
		&slave_qns_gemnoc_sf
	},
	{
		&master_qnm_snoc_sf,
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
	4,
	route_qxm_crypto_0_ebi_hops
};

static struct icb_pair route_qxm_crypto_0_qns_llcc_hops[3] = {
	{
		&master_qxm_crypto_0,
		&slave_qns_a2noc_snoc
	},
	{
		&master_qnm_aggre2_noc,
		&slave_qns_gemnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_llcc
	},
};

static struct icb_route route_qxm_crypto_0_qns_llcc = {
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_SLAVE_LLCC,
	3,
	route_qxm_crypto_0_qns_llcc_hops
};

static struct icb_pair route_qxm_crypto_1_ebi_hops[4] = {
	{
		&master_qxm_crypto_1,
		&slave_qns_a2noc_snoc
	},
	{
		&master_qnm_aggre2_noc,
		&slave_qns_gemnoc_sf
	},
	{
		&master_qnm_snoc_sf,
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
	4,
	route_qxm_crypto_1_ebi_hops
};

static struct icb_pair route_qxm_crypto_1_qns_llcc_hops[3] = {
	{
		&master_qxm_crypto_1,
		&slave_qns_a2noc_snoc
	},
	{
		&master_qnm_aggre2_noc,
		&slave_qns_gemnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_llcc
	},
};

static struct icb_route route_qxm_crypto_1_qns_llcc = {
	ICBID_MASTER_CRYPTO_CORE1,
	ICBID_SLAVE_LLCC,
	3,
	route_qxm_crypto_1_qns_llcc_hops
};

/* NODE AND ROUTE LISTS */
static struct icb_route *icb_route_list[5] = {
	&route_qup2_core_master_qup2_core_slave,
	&route_qxm_crypto_0_ebi,
	&route_qxm_crypto_0_qns_llcc,
	&route_qxm_crypto_1_ebi,
	&route_qxm_crypto_1_qns_llcc,
};

static struct icb_master *icb_master_list[6] = {
	&master_llcc_mc,
	&master_qnm_aggre2_noc,
	&master_qnm_snoc_sf,
	&master_qup2_core_master,
	&master_qxm_crypto_0,
	&master_qxm_crypto_1,
};

static struct icb_slave *icb_slave_list[5] = {
	&slave_ebi,
	&slave_qns_a2noc_snoc,
	&slave_qns_gemnoc_sf,
	&slave_qns_llcc,
	&slave_qup2_core_slave,
};

static struct icb_hw_node *icb_hw_node_list[7] = {
	&bcm_acv,
	&bcm_ce0,
	&bcm_mc0,
	&bcm_qup2,
	&bcm_sh0,
	&bcm_sn0,
	&bcm_sn4,
};

/* EXTERNAL DATA DECLARATIONS */
struct icb_info info = {
	5, /**< number of routes */
	icb_route_list, /**< routes */
	6, /**< number of masters */
	icb_master_list, /**< masters */
	5, /**< number of slaves */
	icb_slave_list, /**< slaves */
	7, /**< number of hw_nodes */
	icb_hw_node_list, /**< hw_nodes */
};
