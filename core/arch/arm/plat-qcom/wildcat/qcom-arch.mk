# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# Wildcat architecture configuration

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_ARM_GICV4,y)

CFG_TZDRAM_SIZE ?= (CFG_TEE_RAM_VA_SIZE + CFG_TA_RAM_VA_SIZE)
CFG_NUM_THREADS ?= 8
