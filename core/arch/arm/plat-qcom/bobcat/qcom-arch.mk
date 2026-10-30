# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

CFG_QCOM_SEC_WDOG ?= y

# TME-Lite fuse programming client; it reaches TME-Lite through tmel_com.
ifeq ($(CFG_QCOM_TMEL_FUSE),y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_FUSE)
endif

# XPU protection for TZDRAM and the OP-TEE DIAG log buffer
CFG_QCOM_XPU_PROTECT ?= y
ifeq ($(CFG_QCOM_XPU_PROTECT),y)
$(call force,CFG_QCOM_XPUV4,y)
endif

CFG_PAS_MD_SLOTS ?= 1
CFG_PAS_TA_HEAP_SIZE ?= (4 * 1024)

# TME-Lite communication stack. The tmel_com client reaches TME-Lite over the
# QMP-Lite mailbox channel, so pull the mailbox framework in with it.
#
# Every TME-Lite client (KM and AUTH here, RNG in target.mk) forces the stack
# on, so disabling it means disabling its clients too.
CFG_QCOM_TMEL_HUK ?= y
ifeq ($(CFG_QCOM_TMEL_HUK),y)
$(call force,CFG_QCOM_TMEL_KM,y,required by CFG_QCOM_TMEL_HUK)
endif

ifeq ($(CFG_QCOM_TMEL_KM),y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_KM)
endif

# ELF image authentication through TME-Lite
CFG_QCOM_TMEL_AUTH ?= y
ifeq ($(CFG_QCOM_TMEL_AUTH),y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_AUTH)
endif

CFG_QCOM_TMEL_COM ?= y
ifeq ($(CFG_QCOM_TMEL_COM),y)
$(call force,CFG_QCOM_MBOX,y,required by CFG_QCOM_TMEL_COM)
$(call force,CFG_QCOM_MBOX_QMP_LITE,y,required by CFG_QCOM_TMEL_COM)
endif

# Reserve carveout at the end of TZDRAM for the TMEL IPC coherent buffers.
CFG_TMECOM_IPCBUF_CARVEOUT_SIZE ?= 0x3000
