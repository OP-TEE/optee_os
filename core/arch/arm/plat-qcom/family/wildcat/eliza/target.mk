# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# One cluster of eight cores, core_pos = MPIDR Aff1.
$(call force,CFG_TEE_CORE_NB_CORE,8)

$(call force,CFG_EMBED_DTB,y)
CFG_EMBED_DTB_SOURCE_FILE ?= qcom/eliza-cqs-evk-emmc.dts

# oem-vm, reserved for a Gunyah VM that is not used with Linux at EL2
CFG_TZDRAM_START ?= 0xf7c00000
CFG_TEE_RAM_VA_SIZE ?= 0x00200000
CFG_TA_RAM_VA_SIZE ?= 0x01c00000

# Nothing programs an access control for TZDRAM
ifneq ($(CFG_INSECURE),y)
$(error Eliza: TZDRAM is not protected, CFG_INSECURE=n is not supported)
endif

$(call force,CFG_QCOM_CSRNG,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
