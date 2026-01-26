# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Altera Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
PLATFORM_FLAVOR ?= agilex5

# ARM Cortex-A55/A76 cores (4 cores total)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)

# Memory layout
# Valid DRAM: 0x80000000-0xEFFFFFFF (1792MB with inline ECC)
# Service Layer: 0x80000000-0x81FFFFFF (32MB, SDM/mailbox)
# Linux kernel loads: 0x80080000-0x825FFFFF (~37MB)
# Place OP-TEE after kernel to avoid overlap: 0x83000000-0x84FFFFFF (32MB)
CFG_TZDRAM_START ?= 0x83000000
CFG_TZDRAM_SIZE ?= 0x02000000

# Use dynamic shared memory from normal world DRAM
$(call force,CFG_CORE_RESERVED_SHM,n)
$(call force,CFG_CORE_DYN_SHM,y)

# Console - 8250 UART
$(call force,CFG_8250_UART,y)
CFG_8250_UART_BASE ?= 0x10C02000
CFG_CONSOLE_UART ?= 0

# GIC
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)

# ATF integration
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Standard features
$(call force,CFG_HWSUPP_MEM_PERM_PXN,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_STATS,y)

# Disable features we don't have
CFG_CRYPTO_WITH_CE ?= n
CFG_WITH_SOFTWARE_PRNG ?= y

# Debug levels - production (2=WARN, shows only errors and warnings)
CFG_TEE_CORE_LOG_LEVEL ?= 2  # 0=none, 1=err, 2=err+warn, 3=+info, 4=+debug

include core/arch/arm/cpu/cortex-armv8-0.mk
