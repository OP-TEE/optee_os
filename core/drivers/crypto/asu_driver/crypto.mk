# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025-2026, Advanced Micro Devices, Inc. All rights reserved.
#
#

ifeq ($(CFG_AMD_ASU_SUPPORT),y)
# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0
$(call force,CFG_CRYPTO_DRV_HASH,y)

CFG_AMD_ASU_HUK ?= y

endif
