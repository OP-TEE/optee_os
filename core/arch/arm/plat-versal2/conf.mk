# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.
#
#

PLATFORM_FLAVOR ?= generic

include core/arch/arm/cpu/cortex-armv8-0.mk

CFG_MMAP_REGIONS ?= 24

# Disable Non-Standard Crypto Algorithms
$(call force,CFG_CRYPTO_SM2_PKE,n)
$(call force,CFG_CRYPTO_SM2_DSA,n)
$(call force,CFG_CRYPTO_SM2_KEP,n)
$(call force,CFG_CRYPTO_SM3,n)
$(call force,CFG_CRYPTO_SM4,n)

# platform does not support paging; explicitly disable CFG_WITH_PAGER
$(call force,CFG_WITH_PAGER,n)

# Platform specific configurations
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_PL011,y)
$(call force,CFG_GIC,y)

CFG_CORE_RESERVED_SHM	?= n
CFG_CORE_DYN_SHM	?= y
CFG_WITH_STATS		?= y
CFG_ARM64_core		?= y

# Enable ARM Crypto Extensions(CE)
$(call force,CFG_CRYPTO_WITH_CE,y)
$(call force,CFG_CRYPTO_WITH_CE82,y)

# Define the number of cores per cluster used in calculating core position.
# The cluster number is shifted by this value and added to the core ID,
# so its value represents log2(cores/cluster).
# For AMD Versal Gen 2 there are 4 clusters and 2 cores per cluster.
$(call force,CFG_CORE_CLUSTER_SHIFT,1)

# By default optee_os is located at the following location.
# This range to contain optee_os, TEE RAM and TA RAM.
# Default size is 128MB.
CFG_TZDRAM_START   ?= 0x1800000
CFG_TZDRAM_SIZE    ?= 0x8000000

# Console selection
# 0 : UART0[pl011, pl011_0] (default)
# 1 : UART1[pl011_1]
CFG_CONSOLE_UART ?= 0

ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,43)
endif

CFG_CORE_HEAP_SIZE ?= 262144
