# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# One cluster of eight cores. MPIDR has MT set with Aff0 = 0, so the
# generic code sees each core as a cluster: core_pos = MPIDR Aff1.
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_CORE_CLUSTER_SHIFT,0)

$(call force,CFG_EMBED_DTB,y)
CFG_EMBED_DTB_SOURCE_FILE ?= qcom/eliza-cqs-evk-emmc.dts

# TEE slot of DARE-TZ, TA RAM runs on into the DARE-TZ TA region
CFG_TZDRAM_START ?= 0xd8200000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x01c00000

$(call force,CFG_QCOM_CSRNG,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)

CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_QCOM_CLK ?= y

CFG_QCOM_PAS_PTA ?= y

ifeq ($(CFG_QCOM_PAS_PTA),y)
CFG_IN_TREE_EARLY_TAS += qcom_pas/cff7d191-7ca0-4784-af13-48223b9a4fbe
endif
