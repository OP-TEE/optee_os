# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Qualcomm Technologies, Inc.

CFG_CRYPTO_DRIVER_DEBUG ?= 0

# Per-algorithm defaults.
CFG_QCOM_CE_AES_ECB ?= n
CFG_QCOM_CE_AES_CBC ?= n

# Derived aggregate flags.
# CFG_QCOM_CE_CIPHER: any of ECB/CBC enabled -> cipher drvcrypt driver.
CFG_QCOM_CE_CIPHER := $(call cfg-one-enabled, \
                          CFG_QCOM_CE_AES_ECB \
                          CFG_QCOM_CE_AES_CBC)
# CFG_QCOM_CE: any algorithm enabled.
CFG_QCOM_CE := $(call cfg-one-enabled, CFG_QCOM_CE_CIPHER)

ifeq ($(CFG_QCOM_CE),y)
$(call force,CFG_CRYPTO_DRIVER,y,Mandated by CFG_QCOM_CE)
$(call force,CFG_QCOM_HWKM,y,Mandated by CFG_QCOM_CE)
endif

ifeq ($(CFG_QCOM_CE_CIPHER),y)
$(call force,CFG_CRYPTO_DRV_CIPHER,y,Mandated by CFG_QCOM_CE_CIPHER)
endif
