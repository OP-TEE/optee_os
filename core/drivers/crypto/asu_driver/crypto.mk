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

ifeq ($(CFG_AMD_ASU_ECC),y)
$(call force,CFG_CRYPTO_DRV_ECC,y)
$(call force,CFG_CRYPTO_DRV_ACIPHER,y)
endif

ifeq ($(CFG_AMD_ASU_CIPHER),y)
$(call force,CFG_CRYPTO_DRV_CIPHER,y)
CFG_AMD_ASU_SW_FALLBACK ?= y
endif

ifeq ($(CFG_AMD_ASU_RSA),y)
$(call force,CFG_CRYPTO_DRV_ACIPHER,y)
$(call force,CFG_CRYPTO_DRV_RSA,y)
endif

endif
