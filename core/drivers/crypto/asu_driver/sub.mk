 # SPDX-License-Identifier: BSD-2-Clause
 #
 # Copyright (c) 2025-2026, Advanced Micro Devices, Inc. All rights reserved.
 #
 #


srcs-$(CFG_AMD_ASU_HASH) += asu_hash.c
srcs-$(CFG_AMD_ASU_TRNG) += asu_trng.c
srcs-$(CFG_AMD_ASU_HUK) += asu_huk.c
srcs-$(CFG_AMD_ASU_ECC) += asu_ecc.c
srcs-$(CFG_AMD_ASU_CIPHER) += asu_cipher.c

ifeq ($(CFG_AMD_ASU_ECC),y)
# This curves configuration aligns enabled ECC/ECDH curves with ASU FW default
# configurations. For the disabled curves, driver will use software fallback
# operations. Make sure to configure ASU FW with enabled curves to prevent
# any testcase failures
CFG_AMD_ASU_ECC_CURVE_NIST_P192 ?= n
CFG_AMD_ASU_ECC_CURVE_NIST_P224 ?= n
CFG_AMD_ASU_ECC_CURVE_NIST_P256 ?= y
CFG_AMD_ASU_ECC_CURVE_NIST_P384 ?= n
CFG_AMD_ASU_ECC_CURVE_NIST_P521 ?= n
endif
