// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QTI ICB (Interconnect Bus) driver - Shikra target data.
 */

#include "icbuarbi.h"

/* CLOCK DECLARATIONS */
/* CNOC */
static uint32_t clock_cnoc_reqs[5] = {0};
static struct icb_clock clock_cnoc_info = {
	"/clk/cnoc", /**< name */
	NULL, /**< id */
	false, /**< dirty */
	0, /**< state */
	5, /**< num_requests */
	clock_cnoc_reqs, /**< requests */
};

/* MASTER DECLARATIONS */
/* QUP0_CORE_MASTER */
static struct icb_master master_qup0_core_master = {
	ICBID_MASTER_QUP_CORE_0, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* HWKM_CORE_MASTER */
static struct icb_master master_hwkm_core_master = {
	ICBID_MASTER_HWKM_CORE, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* PKA_CORE_MASTER */
static struct icb_master master_pka_core_master = {
	ICBID_MASTER_PKA_CORE, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* CRYPTO_C0 */
static struct icb_master master_crypto_c0 = {
	ICBID_MASTER_CRYPTO_CORE0, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	650, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNM_SNOC_CNOC */
static struct icb_clock_handle master_qnm_snoc_cnoc_clocks[1] = {
	{
		&clock_cnoc_info,
		0,
	},
};

static struct icb_master master_qnm_snoc_cnoc = {
	ICBID_MASTER_SNOC_CNOC, /**< id */
	{0, 0}, /**< curr_req */
	false, /**< remote node? */
	8, /**< width in bytes */
	1, /**< num_clocks */
	master_qnm_snoc_cnoc_clocks, /**< clocks */
};

/* LLCC_MC */
static struct icb_master master_llcc_mc = {
	ICBID_MASTER_LLCC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNM_SNOC_SF */
static struct icb_master master_qnm_snoc_sf = {
	ICBID_MASTER_SNOC_SF_MEM_NOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* XM_APPS */
static struct icb_master master_xm_apps = {
	ICBID_MASTER_APPSS_PROC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNM_ANOC_SNOC */
static struct icb_master master_qnm_anoc_snoc = {
	ICBID_MASTER_ANOC_SNOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNM_MEMNOC_SNOC */
static struct icb_master master_qnm_memnoc_snoc = {
	ICBID_MASTER_MEMNOC_SNOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* MAS_CR_VIRT_A1NOC */
static struct icb_master master_mas_cr_virt_a1noc = {
	ICBID_MASTER_CRVIRT_A1NOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QHM_QUP0 */
static struct icb_master master_qhm_qup0 = {
	ICBID_MASTER_QUP_0, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* SLAVE DECLARATIONS */
/* HWKM_CORE_SLAVE */
static struct icb_slave slave_hwkm_core_slave = {
	ICBID_SLAVE_HWKM_CORE, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* PKA_CORE_SLAVE */
static struct icb_slave slave_pka_core_slave = {
	ICBID_SLAVE_PKA_CORE, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QUP0_CORE_SLAVE */
static struct icb_slave slave_qup0_core_slave = {
	ICBID_SLAVE_QUP_CORE_0, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* SLV_CR_VIRT_A1NOC */
static struct icb_slave slave_slv_cr_virt_a1noc = {
	ICBID_SLAVE_CRVIRT_A1NOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QHS_CRYPTO0_CFG */
static struct icb_clock_handle slave_qhs_crypto0_cfg_clocks[1] = {
	{
		&clock_cnoc_info,
		1,
	},
};

static struct icb_slave slave_qhs_crypto0_cfg = {
	ICBID_SLAVE_CRYPTO_0_CFG, /**< id */
	{0, 0}, /**< curr_req */
	false, /**< remote node? */
	4, /**< width in bytes */
	1, /**< num_clocks */
	slave_qhs_crypto0_cfg_clocks, /**< clocks */
};

/* QHS_HWKM */
static struct icb_clock_handle slave_qhs_hwkm_clocks[1] = {
	{
		&clock_cnoc_info,
		2,
	},
};

static struct icb_slave slave_qhs_hwkm = {
	ICBID_SLAVE_HWKM, /**< id */
	{0, 0}, /**< curr_req */
	false, /**< remote node? */
	4, /**< width in bytes */
	1, /**< num_clocks */
	slave_qhs_hwkm_clocks, /**< clocks */
};

/* QHS_PKA_WRAPPER */
static struct icb_clock_handle slave_qhs_pka_wrapper_clocks[1] = {
	{
		&clock_cnoc_info,
		3,
	},
};

static struct icb_slave slave_qhs_pka_wrapper = {
	ICBID_SLAVE_PKA_WRAPPER_CFG, /**< id */
	{0, 0}, /**< curr_req */
	false, /**< remote node? */
	4, /**< width in bytes */
	1, /**< num_clocks */
	slave_qhs_pka_wrapper_clocks, /**< clocks */
};

/* QHS_QUP0 */
static struct icb_clock_handle slave_qhs_qup0_clocks[1] = {
	{
		&clock_cnoc_info,
		4,
	},
};

static struct icb_slave slave_qhs_qup0 = {
	ICBID_SLAVE_QUP_0, /**< id */
	{0, 0}, /**< curr_req */
	false, /**< remote node? */
	4, /**< width in bytes */
	1, /**< num_clocks */
	slave_qhs_qup0_clocks, /**< clocks */
};

/* EBI */
static struct icb_slave slave_ebi = {
	ICBID_SLAVE_EBI1, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	4, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNS_LLCC */
static struct icb_slave slave_qns_llcc = {
	ICBID_SLAVE_LLCC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNS_MEMNOC_SNOC */
static struct icb_slave slave_qns_memnoc_snoc = {
	ICBID_SLAVE_MEMNOC_SNOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNS_MEMNOC_SF */
static struct icb_slave slave_qns_memnoc_sf = {
	ICBID_SLAVE_MEMNOC_SF, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNS_SNOC_CNOC */
static struct icb_slave slave_qns_snoc_cnoc = {
	ICBID_SLAVE_SNOC_CNOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QXS_IMEM */
static struct icb_slave slave_qxs_imem = {
	ICBID_SLAVE_IMEM, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	8, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* QNS_ANOC_SNOC */
static struct icb_slave slave_qns_anoc_snoc = {
	ICBID_SLAVE_ANOC_SNOC, /**< id */
	{0, 0}, /**< curr_req */
	true, /**< remote node? */
	16, /**< width in bytes */
	0, /**< num_clocks */
	NULL, /**< clocks */
};

/* TOPOLOGY ROUTE DECLARATIONS */
static struct icb_pair route_crypto_c0_ebi_hops[5] = {
	{
		&master_crypto_c0,
		&slave_slv_cr_virt_a1noc
	},
	{
		&master_mas_cr_virt_a1noc,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
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

static struct icb_route route_crypto_c0_ebi = {
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_SLAVE_EBI1,
	5,
	route_crypto_c0_ebi_hops
};

static struct icb_pair route_crypto_c0_qns_llcc_hops[4] = {
	{
		&master_crypto_c0,
		&slave_slv_cr_virt_a1noc
	},
	{
		&master_mas_cr_virt_a1noc,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_llcc
	},
};

static struct icb_route route_crypto_c0_qns_llcc = {
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_SLAVE_LLCC,
	4,
	route_crypto_c0_qns_llcc_hops
};

static struct icb_pair route_crypto_c0_qxs_imem_hops[5] = {
	{
		&master_crypto_c0,
		&slave_slv_cr_virt_a1noc
	},
	{
		&master_mas_cr_virt_a1noc,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qxs_imem
	},
};

static struct icb_route route_crypto_c0_qxs_imem = {
	ICBID_MASTER_CRYPTO_CORE0,
	ICBID_SLAVE_IMEM,
	5,
	route_crypto_c0_qxs_imem_hops
};

static struct icb_pair route_hwkm_core_master_hwkm_core_slave_hops[1] = {
	{
		&master_hwkm_core_master,
		&slave_hwkm_core_slave
	},
};

static struct icb_route route_hwkm_core_master_hwkm_core_slave = {
	ICBID_MASTER_HWKM_CORE,
	ICBID_SLAVE_HWKM_CORE,
	1,
	route_hwkm_core_master_hwkm_core_slave_hops
};

static struct icb_pair route_llcc_mc_ebi_hops[1] = {
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_llcc_mc_ebi = {
	ICBID_MASTER_LLCC,
	ICBID_SLAVE_EBI1,
	1,
	route_llcc_mc_ebi_hops
};

static struct icb_pair route_pka_core_master_pka_core_slave_hops[1] = {
	{
		&master_pka_core_master,
		&slave_pka_core_slave
	},
};

static struct icb_route route_pka_core_master_pka_core_slave = {
	ICBID_MASTER_PKA_CORE,
	ICBID_SLAVE_PKA_CORE,
	1,
	route_pka_core_master_pka_core_slave_hops
};

static struct icb_pair route_qhm_qup0_ebi_hops[4] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
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

static struct icb_pair route_qhm_qup0_qhs_crypto0_cfg_hops[5] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_crypto0_cfg
	},
};

static struct icb_route route_qhm_qup0_qhs_crypto0_cfg = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_CRYPTO_0_CFG,
	5,
	route_qhm_qup0_qhs_crypto0_cfg_hops
};

static struct icb_pair route_qhm_qup0_qhs_hwkm_hops[5] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_hwkm
	},
};

static struct icb_route route_qhm_qup0_qhs_hwkm = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_HWKM,
	5,
	route_qhm_qup0_qhs_hwkm_hops
};

static struct icb_pair route_qhm_qup0_qhs_pka_wrapper_hops[5] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_pka_wrapper
	},
};

static struct icb_route route_qhm_qup0_qhs_pka_wrapper = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_PKA_WRAPPER_CFG,
	5,
	route_qhm_qup0_qhs_pka_wrapper_hops
};

static struct icb_pair route_qhm_qup0_qhs_qup0_hops[5] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_qup0
	},
};

static struct icb_route route_qhm_qup0_qhs_qup0 = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_QUP_0,
	5,
	route_qhm_qup0_qhs_qup0_hops
};

static struct icb_pair route_qhm_qup0_qns_llcc_hops[3] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_llcc
	},
};

static struct icb_route route_qhm_qup0_qns_llcc = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_LLCC,
	3,
	route_qhm_qup0_qns_llcc_hops
};

static struct icb_pair route_qhm_qup0_qxs_imem_hops[4] = {
	{
		&master_qhm_qup0,
		&slave_qns_anoc_snoc
	},
	{
		&master_qnm_anoc_snoc,
		&slave_qns_memnoc_sf
	},
	{
		&master_qnm_snoc_sf,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qxs_imem
	},
};

static struct icb_route route_qhm_qup0_qxs_imem = {
	ICBID_MASTER_QUP_0,
	ICBID_SLAVE_IMEM,
	4,
	route_qhm_qup0_qxs_imem_hops
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

static struct icb_pair route_xm_apps_ebi_hops[2] = {
	{
		&master_xm_apps,
		&slave_qns_llcc
	},
	{
		&master_llcc_mc,
		&slave_ebi
	},
};

static struct icb_route route_xm_apps_ebi = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_EBI1,
	2,
	route_xm_apps_ebi_hops
};

static struct icb_pair route_xm_apps_qhs_crypto0_cfg_hops[3] = {
	{
		&master_xm_apps,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_crypto0_cfg
	},
};

static struct icb_route route_xm_apps_qhs_crypto0_cfg = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_CRYPTO_0_CFG,
	3,
	route_xm_apps_qhs_crypto0_cfg_hops
};

static struct icb_pair route_xm_apps_qhs_hwkm_hops[3] = {
	{
		&master_xm_apps,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_hwkm
	},
};

static struct icb_route route_xm_apps_qhs_hwkm = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_HWKM,
	3,
	route_xm_apps_qhs_hwkm_hops
};

static struct icb_pair route_xm_apps_qhs_pka_wrapper_hops[3] = {
	{
		&master_xm_apps,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_pka_wrapper
	},
};

static struct icb_route route_xm_apps_qhs_pka_wrapper = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_PKA_WRAPPER_CFG,
	3,
	route_xm_apps_qhs_pka_wrapper_hops
};

static struct icb_pair route_xm_apps_qhs_qup0_hops[3] = {
	{
		&master_xm_apps,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qns_snoc_cnoc
	},
	{
		&master_qnm_snoc_cnoc,
		&slave_qhs_qup0
	},
};

static struct icb_route route_xm_apps_qhs_qup0 = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_QUP_0,
	3,
	route_xm_apps_qhs_qup0_hops
};

static struct icb_pair route_xm_apps_qns_llcc_hops[1] = {
	{
		&master_xm_apps,
		&slave_qns_llcc
	},
};

static struct icb_route route_xm_apps_qns_llcc = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_LLCC,
	1,
	route_xm_apps_qns_llcc_hops
};

static struct icb_pair route_xm_apps_qxs_imem_hops[2] = {
	{
		&master_xm_apps,
		&slave_qns_memnoc_snoc
	},
	{
		&master_qnm_memnoc_snoc,
		&slave_qxs_imem
	},
};

static struct icb_route route_xm_apps_qxs_imem = {
	ICBID_MASTER_APPSS_PROC,
	ICBID_SLAVE_IMEM,
	2,
	route_xm_apps_qxs_imem_hops
};

/* NODE AND ROUTE LISTS */
static struct icb_clock *icb_clock_list[1] = {
	&clock_cnoc_info,
};

static struct icb_route *icb_route_list[21] = {
	&route_crypto_c0_ebi,
	&route_crypto_c0_qns_llcc,
	&route_crypto_c0_qxs_imem,
	&route_hwkm_core_master_hwkm_core_slave,
	&route_llcc_mc_ebi,
	&route_pka_core_master_pka_core_slave,
	&route_qhm_qup0_ebi,
	&route_qhm_qup0_qhs_crypto0_cfg,
	&route_qhm_qup0_qhs_hwkm,
	&route_qhm_qup0_qhs_pka_wrapper,
	&route_qhm_qup0_qhs_qup0,
	&route_qhm_qup0_qns_llcc,
	&route_qhm_qup0_qxs_imem,
	&route_qup0_core_master_qup0_core_slave,
	&route_xm_apps_ebi,
	&route_xm_apps_qhs_crypto0_cfg,
	&route_xm_apps_qhs_hwkm,
	&route_xm_apps_qhs_pka_wrapper,
	&route_xm_apps_qhs_qup0,
	&route_xm_apps_qns_llcc,
	&route_xm_apps_qxs_imem,
};

/* EXTERNAL DATA DECLARATIONS */
struct icb_info info = {
	21, /**< number of routes */
	icb_route_list, /**< routes */
	1, /**< number of clocks */
	icb_clock_list, /**< clocks */
};
