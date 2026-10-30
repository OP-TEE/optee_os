// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QTI ICB (Interconnect Bus) driver - Lemans target data.
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

/* CN0 */
static struct icb_hw_request bcm_cn0_requests[1];
static struct icb_hw_node bcm_cn0 = {
	NULL, /**< node linkage */
	"CN0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_cn0_requests}, /**< request_list */
	0, /**< output */
};

/* CN1 */
static struct icb_hw_request bcm_cn1_requests[2];
static struct icb_hw_node bcm_cn1 = {
	NULL, /**< node linkage */
	"CN1", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 2, bcm_cn1_requests}, /**< request_list */
	0, /**< output */
};

/* CN2 */
static struct icb_hw_request bcm_cn2_requests[4];
static struct icb_hw_node bcm_cn2 = {
	NULL, /**< node linkage */
	"CN2", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 4, bcm_cn2_requests}, /**< request_list */
	0, /**< output */
};

/* HK0 */
static struct icb_hw_request bcm_hk0_requests[1];
static struct icb_hw_node bcm_hk0 = {
	NULL, /**< node linkage */
	"HK0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_hk0_requests}, /**< request_list */
	0, /**< output */
};

/* IP0 */
static struct icb_hw_request bcm_ip0_requests[1];
static struct icb_hw_node bcm_ip0 = {
	NULL, /**< node linkage */
	"IP0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_ip0_requests}, /**< request_list */
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

/* PKA0 */
static struct icb_hw_request bcm_pka0_requests[1];
static struct icb_hw_node bcm_pka0 = {
	NULL, /**< node linkage */
	"PKA0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_pka0_requests}, /**< request_list */
	0, /**< output */
};

/* QUP0 */
static struct icb_hw_request bcm_qup0_requests[1];
static struct icb_hw_node bcm_qup0 = {
	NULL, /**< node linkage */
	"QUP0", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_qup0_requests}, /**< request_list */
	0, /**< output */
};

/* QUP1 */
static struct icb_hw_request bcm_qup1_requests[1];
static struct icb_hw_node bcm_qup1 = {
	NULL, /**< node linkage */
	"QUP1", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_qup1_requests}, /**< request_list */
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

/* SH2 */
static struct icb_hw_request bcm_sh2_requests[1];
static struct icb_hw_node bcm_sh2 = {
	NULL, /**< node linkage */
	"SH2", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 1, bcm_sh2_requests}, /**< request_list */
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

/* SN3 */
static struct icb_hw_request bcm_sn3_requests[2];
static struct icb_hw_node bcm_sn3 = {
	NULL, /**< node linkage */
	"SN3", /**< name */
	ICB_HW_NODE_KIND_BANDWIDTH, /**< type */
	0, /**< hw_id */
	0, /**< width */
	0, /**< bw_unit */
	0, /**< clk_id */
	false, /**< is_dirty */
	0, /**< vote */
	{0, 0}, /**< state */
	{0, 2, bcm_sn3_requests}, /**< request_list */
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
/* CHM_APPS */
static struct icb_hw_node *master_chm_apps_hw_nodes[] = {
	&bcm_sh2,
};

static struct icb_master master_chm_apps = {
	ICBID_MASTER_APPSS_PROC,
	32, /**< width */
	4, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_chm_apps_hw_nodes, /**< hw nodes */
};

/* HKWM_CORE_MASTER */
static struct icb_master master_hkwm_core_master = {
	ICBID_MASTER_HWKM_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* IPA_CORE_MASTER */
static struct icb_master master_ipa_core_master = {
	ICBID_MASTER_IPA_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

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

/* PKE_CORE_MASTER */
static struct icb_master master_pke_core_master = {
	ICBID_MASTER_PKA_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHM_QUP0 */
static struct icb_master master_qhm_qup0 = {
	ICBID_MASTER_QUP_0,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHM_QUP1 */
static struct icb_master master_qhm_qup1 = {
	ICBID_MASTER_QUP_1,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QHM_QUP2 */
static struct icb_master master_qhm_qup2 = {
	ICBID_MASTER_QUP_2,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QNM_AGGRE1_NOC */
static struct icb_hw_node *master_qnm_aggre1_noc_hw_nodes[] = {
	&bcm_sn3,
};

static struct icb_master master_qnm_aggre1_noc = {
	ICBID_MASTER_A1NOC_SNOC,
	32, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qnm_aggre1_noc_hw_nodes, /**< hw nodes */
};

/* QNM_AGGRE2_NOC */
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

/* QNM_GEMNOC_CNOC */
static struct icb_hw_node *master_qnm_gemnoc_cnoc_hw_nodes[] = {
	&bcm_cn0,
};

static struct icb_master master_qnm_gemnoc_cnoc = {
	ICBID_MASTER_GEM_NOC_CNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	master_qnm_gemnoc_cnoc_hw_nodes, /**< hw nodes */
};

/* QNM_SNOC_SF */
static struct icb_master master_qnm_snoc_sf = {
	ICBID_MASTER_SNOC_SF_MEM_NOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QUP0_CORE_MASTER */
static struct icb_master master_qup0_core_master = {
	ICBID_MASTER_QUP_CORE_0,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QUP1_CORE_MASTER */
static struct icb_master master_qup1_core_master = {
	ICBID_MASTER_QUP_CORE_1,
	4, /**< width */
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

/* QUP3_CORE_MASTER */
static struct icb_master master_qup3_core_master = {
	ICBID_MASTER_QUP_CORE_3,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
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

/* QXM_QUP3 */
static struct icb_master master_qxm_qup3 = {
	ICBID_MASTER_QUP_3,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
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

/* HKWM_CORE_SLAVE */
static struct icb_hw_node *slave_hkwm_core_slave_hw_nodes[] = {
	&bcm_hk0,
};

static struct icb_slave slave_hkwm_core_slave = {
	ICBID_SLAVE_HWKM_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_hkwm_core_slave_hw_nodes, /**< hw nodes */
};

/* IPA_CORE_SLAVE */
static struct icb_hw_node *slave_ipa_core_slave_hw_nodes[] = {
	&bcm_ip0,
};

static struct icb_slave slave_ipa_core_slave = {
	ICBID_SLAVE_IPA_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_ipa_core_slave_hw_nodes, /**< hw nodes */
};

/* PKE_CORE_SLAVE */
static struct icb_hw_node *slave_pke_core_slave_hw_nodes[] = {
	&bcm_pka0,
};

static struct icb_slave slave_pke_core_slave = {
	ICBID_SLAVE_PKA_CORE,
	8, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_pke_core_slave_hw_nodes, /**< hw nodes */
};

/* QHS_CRYPTO0_CFG */
static struct icb_hw_node *slave_qhs_crypto0_cfg_hw_nodes[] = {
	&bcm_cn1,
};

static struct icb_slave slave_qhs_crypto0_cfg = {
	ICBID_SLAVE_CRYPTO_0_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_crypto0_cfg_hw_nodes, /**< hw nodes */
};

/* QHS_PKE_WRAPPER_CFG */
static struct icb_hw_node *slave_qhs_pke_wrapper_cfg_hw_nodes[] = {
	&bcm_cn1,
};

static struct icb_slave slave_qhs_pke_wrapper_cfg = {
	ICBID_SLAVE_PKA_WRAPPER_CFG,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_pke_wrapper_cfg_hw_nodes, /**< hw nodes */
};

/* QHS_QUP0 */
static struct icb_hw_node *slave_qhs_qup0_hw_nodes[] = {
	&bcm_cn2,
};

static struct icb_slave slave_qhs_qup0 = {
	ICBID_SLAVE_QUP_0,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_qup0_hw_nodes, /**< hw nodes */
};

/* QHS_QUP1 */
static struct icb_hw_node *slave_qhs_qup1_hw_nodes[] = {
	&bcm_cn2,
};

static struct icb_slave slave_qhs_qup1 = {
	ICBID_SLAVE_QUP_1,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_qup1_hw_nodes, /**< hw nodes */
};

/* QHS_QUP2 */
static struct icb_hw_node *slave_qhs_qup2_hw_nodes[] = {
	&bcm_cn2,
};

static struct icb_slave slave_qhs_qup2 = {
	ICBID_SLAVE_QUP_2,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_qup2_hw_nodes, /**< hw nodes */
};

/* QHS_QUP3 */
static struct icb_hw_node *slave_qhs_qup3_hw_nodes[] = {
	&bcm_cn2,
};

static struct icb_slave slave_qhs_qup3 = {
	ICBID_SLAVE_QUP_3,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qhs_qup3_hw_nodes, /**< hw nodes */
};

/* QNS_A1NOC_SNOC */
static struct icb_hw_node *slave_qns_a1noc_snoc_hw_nodes[] = {
	&bcm_sn3,
};

static struct icb_slave slave_qns_a1noc_snoc = {
	ICBID_SLAVE_A1NOC_SNOC,
	32, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qns_a1noc_snoc_hw_nodes, /**< hw nodes */
};

/* QNS_A2NOC_SNOC */
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

/* QNS_GEM_NOC_CNOC */
static struct icb_slave slave_qns_gem_noc_cnoc = {
	ICBID_SLAVE_GEM_NOC_CNOC,
	16, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	0, /**< number of hw_nodes */
	NULL, /**< hw nodes */
};

/* QNS_GEMNOC_SF */
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

/* QNS_LLCC */
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

/* QUP0_CORE_SLAVE */
static struct icb_hw_node *slave_qup0_core_slave_hw_nodes[] = {
	&bcm_qup0,
};

static struct icb_slave slave_qup0_core_slave = {
	ICBID_SLAVE_QUP_CORE_0,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qup0_core_slave_hw_nodes, /**< hw nodes */
};

/* QUP1_CORE_SLAVE */
static struct icb_hw_node *slave_qup1_core_slave_hw_nodes[] = {
	&bcm_qup1,
};

static struct icb_slave slave_qup1_core_slave = {
	ICBID_SLAVE_QUP_CORE_1,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qup1_core_slave_hw_nodes, /**< hw nodes */
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

/* QUP3_CORE_SLAVE */
static struct icb_hw_node *slave_qup3_core_slave_hw_nodes[] = {
	&bcm_qup2,
};

static struct icb_slave slave_qup3_core_slave = {
	ICBID_SLAVE_QUP_CORE_3,
	4, /**< width */
	1, /**< num ports */
	{0, 0}, /**< state */
	{0, 0, NULL}, /**< request_list */
	1, /**< number of hw_nodes */
	slave_qup3_core_slave_hw_nodes, /**< hw nodes */
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

static struct icb_pair route_chm_apps_qhs_crypto0_cfg_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_crypto0_cfg
	},
};

static struct icb_route route_chm_apps_qhs_crypto0_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_CRYPTO_0_CFG,
	2,
	route_chm_apps_qhs_crypto0_cfg_hops
};

static struct icb_pair route_chm_apps_qhs_pke_wrapper_cfg_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_pke_wrapper_cfg
	},
};

static struct icb_route route_chm_apps_qhs_pke_wrapper_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_PKA_WRAPPER_CFG,
	2,
	route_chm_apps_qhs_pke_wrapper_cfg_hops
};

static struct icb_pair route_chm_apps_qhs_qup0_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_qup0
	},
};

static struct icb_route route_chm_apps_qhs_qup0 = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_QUP_0,
	2,
	route_chm_apps_qhs_qup0_hops
};

static struct icb_pair route_chm_apps_qhs_qup1_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_qup1
	},
};

static struct icb_route route_chm_apps_qhs_qup1 = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_QUP_1,
	2,
	route_chm_apps_qhs_qup1_hops
};

static struct icb_pair route_chm_apps_qhs_qup2_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_qup2
	},
};

static struct icb_route route_chm_apps_qhs_qup2 = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_QUP_2,
	2,
	route_chm_apps_qhs_qup2_hops
};

static struct icb_pair route_chm_apps_qhs_qup3_hops[2] = {
	{
		&master_chm_apps,
		&slave_qns_gem_noc_cnoc
	},
	{
		&master_qnm_gemnoc_cnoc,
		&slave_qhs_qup3
	},
};

static struct icb_route route_chm_apps_qhs_qup3 = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_QUP_3,
	2,
	route_chm_apps_qhs_qup3_hops
};

static struct icb_pair route_hkwm_core_master_hkwm_core_slave_hops[1] = {
	{
		&master_hkwm_core_master,
		&slave_hkwm_core_slave
	},
};

static struct icb_route route_hkwm_core_master_hkwm_core_slave = {
	ICBID_MASTER_HWKM_CORE,
	ICBID_SLAVE_HWKM_CORE,
	1,
	route_hkwm_core_master_hkwm_core_slave_hops
};

static struct icb_pair route_ipa_core_master_ipa_core_slave_hops[1] = {
	{
		&master_ipa_core_master,
		&slave_ipa_core_slave
	},
};

static struct icb_route route_ipa_core_master_ipa_core_slave = {
	ICBID_MASTER_IPA_CORE,
	ICBID_SLAVE_IPA_CORE,
	1,
	route_ipa_core_master_ipa_core_slave_hops
};

static struct icb_pair route_pke_core_master_pke_core_slave_hops[1] = {
	{
		&master_pke_core_master,
		&slave_pke_core_slave
	},
};

static struct icb_route route_pke_core_master_pke_core_slave = {
	ICBID_MASTER_PKA_CORE,
	ICBID_SLAVE_PKA_CORE,
	1,
	route_pke_core_master_pke_core_slave_hops
};

static struct icb_pair route_qhm_qup0_ebi_hops[4] = {
	{
		&master_qhm_qup0,
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

static struct icb_route route_qhm_qup0_ebi = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_EBI1,
	4,
	route_qhm_qup0_ebi_hops
};

static struct icb_pair route_qhm_qup1_ebi_hops[4] = {
	{
		&master_qhm_qup1,
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

static struct icb_route route_qhm_qup1_ebi = {
	ICBID_MASTER_QUP_1,
	ICBID_SLAVE_EBI1,
	4,
	route_qhm_qup1_ebi_hops
};

static struct icb_pair route_qhm_qup2_ebi_hops[4] = {
	{
		&master_qhm_qup2,
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

static struct icb_route route_qhm_qup2_ebi = {
	ICBID_MASTER_QUP_2,
	ICBID_SLAVE_EBI1,
	4,
	route_qhm_qup2_ebi_hops
};

static struct icb_pair route_qup0_core_master_qup0_core_slave_hops[1] = {
	{
		&master_qup0_core_master,
		&slave_qup0_core_slave
	},
};

static struct icb_route route_qup0_core_master_qup0_core_slave = {
	ICBID_MASTER_QUP_CORE_0,
	ICBID_SLAVE_QUP_CORE_0,
	1,
	route_qup0_core_master_qup0_core_slave_hops
};

static struct icb_pair route_qup1_core_master_qup1_core_slave_hops[1] = {
	{
		&master_qup1_core_master,
		&slave_qup1_core_slave
	},
};

static struct icb_route route_qup1_core_master_qup1_core_slave = {
	ICBID_MASTER_QUP_CORE_1,
	ICBID_SLAVE_QUP_CORE_1,
	1,
	route_qup1_core_master_qup1_core_slave_hops
};

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

static struct icb_pair route_qup3_core_master_qup3_core_slave_hops[1] = {
	{
		&master_qup3_core_master,
		&slave_qup3_core_slave
	},
};

static struct icb_route route_qup3_core_master_qup3_core_slave = {
	ICBID_MASTER_QUP_CORE_3,
	ICBID_SLAVE_QUP_CORE_3,
	1,
	route_qup3_core_master_qup3_core_slave_hops
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

static struct icb_pair route_qxm_qup3_ebi_hops[4] = {
	{
		&master_qxm_qup3,
		&slave_qns_a1noc_snoc
	},
	{
		&master_qnm_aggre1_noc,
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

static struct icb_route route_qxm_qup3_ebi = {
	ICBID_MASTER_QUP_3,
	ICBID_SLAVE_EBI1,
	4,
	route_qxm_qup3_ebi_hops
};

/* NODE AND ROUTE LISTS */
static struct icb_route *icb_route_list[20] = {
	&route_chm_apps_ebi,
	&route_chm_apps_qhs_crypto0_cfg,
	&route_chm_apps_qhs_pke_wrapper_cfg,
	&route_chm_apps_qhs_qup0,
	&route_chm_apps_qhs_qup1,
	&route_chm_apps_qhs_qup2,
	&route_chm_apps_qhs_qup3,
	&route_hkwm_core_master_hkwm_core_slave,
	&route_ipa_core_master_ipa_core_slave,
	&route_pke_core_master_pke_core_slave,
	&route_qhm_qup0_ebi,
	&route_qhm_qup1_ebi,
	&route_qhm_qup2_ebi,
	&route_qup0_core_master_qup0_core_slave,
	&route_qup1_core_master_qup1_core_slave,
	&route_qup2_core_master_qup2_core_slave,
	&route_qup3_core_master_qup3_core_slave,
	&route_qxm_crypto_0_ebi,
	&route_qxm_crypto_1_ebi,
	&route_qxm_qup3_ebi,
};

static struct icb_master *icb_master_list[19] = {
	&master_chm_apps,
	&master_hkwm_core_master,
	&master_ipa_core_master,
	&master_llcc_mc,
	&master_pke_core_master,
	&master_qhm_qup0,
	&master_qhm_qup1,
	&master_qhm_qup2,
	&master_qnm_aggre1_noc,
	&master_qnm_aggre2_noc,
	&master_qnm_gemnoc_cnoc,
	&master_qnm_snoc_sf,
	&master_qup0_core_master,
	&master_qup1_core_master,
	&master_qup2_core_master,
	&master_qup3_core_master,
	&master_qxm_crypto_0,
	&master_qxm_crypto_1,
	&master_qxm_qup3,
};

static struct icb_slave *icb_slave_list[19] = {
	&slave_ebi,
	&slave_hkwm_core_slave,
	&slave_ipa_core_slave,
	&slave_pke_core_slave,
	&slave_qhs_crypto0_cfg,
	&slave_qhs_pke_wrapper_cfg,
	&slave_qhs_qup0,
	&slave_qhs_qup1,
	&slave_qhs_qup2,
	&slave_qhs_qup3,
	&slave_qns_a1noc_snoc,
	&slave_qns_a2noc_snoc,
	&slave_qns_gem_noc_cnoc,
	&slave_qns_gemnoc_sf,
	&slave_qns_llcc,
	&slave_qup0_core_slave,
	&slave_qup1_core_slave,
	&slave_qup2_core_slave,
	&slave_qup3_core_slave,
};

static struct icb_hw_node *icb_hw_node_list[17] = {
	&bcm_acv,
	&bcm_ce0,
	&bcm_cn0,
	&bcm_cn1,
	&bcm_cn2,
	&bcm_hk0,
	&bcm_ip0,
	&bcm_mc0,
	&bcm_pka0,
	&bcm_qup0,
	&bcm_qup1,
	&bcm_qup2,
	&bcm_sh0,
	&bcm_sh2,
	&bcm_sn0,
	&bcm_sn3,
	&bcm_sn4,
};

/* EXTERNAL DATA DECLARATIONS */
struct icb_info info = {
	20, /**< number of routes */
	icb_route_list, /**< routes */
	19, /**< number of masters */
	icb_master_list, /**< masters */
	19, /**< number of slaves */
	icb_slave_list, /**< slaves */
	17, /**< number of hw_nodes */
	icb_hw_node_list, /**< hw_nodes */
};
