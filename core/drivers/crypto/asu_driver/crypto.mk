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

# Minimum ASUFW version OP-TEE requires to boot (see fw_compat_check()).
# Boot panics if the ASUFW version reported via RTCA is older than this.
CFG_AMD_ASU_MINVER_MAJ ?= 2
CFG_AMD_ASU_MINVER_MNR ?= 0

CFG_AMD_ASU_HUK ?= y

# Minimum ASU HUK module version required to trust the HUK fetched from
# ASUFW (see asu_fetch_and_cache_huk()). There is no software fallback for
# the HUK, so a mismatch is a hard error rather than a degraded mode.
CFG_AMD_ASU_HUK_MINVER_MAJ ?= 1
CFG_AMD_ASU_HUK_MINVER_MNR ?= 0

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

# Minimum ASU RSA module version required to use HW-accelerated RSA (see
# asu_rsa_init()). Below this, or when the FeatureCaps bit for the
# requested operation is not set, the driver falls back to software RSA.
CFG_AMD_ASU_RSA_MINVER_MAJ ?= 2
CFG_AMD_ASU_RSA_MINVER_MNR ?= 0
endif

ifeq ($(CFG_AMD_ASU_HMAC),y)
$(call force,CFG_CRYPTO_DRV_MAC,y)
endif

ifeq ($(CFG_AMD_ASU_AUTHENC),y)
$(call force,CFG_CRYPTO_DRV_AUTHENC,y)
$(call force,CFG_AMD_ASU_SW_FALLBACK,y)
endif

endif
