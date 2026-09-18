# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

CFG_QCOM_SEC_WDOG ?= y

# XPU protection for TZDRAM and the OP-TEE DIAG log buffer
CFG_QCOM_XPU_PROTECT ?= y
ifeq ($(CFG_QCOM_XPU_PROTECT),y)
$(call force,CFG_QCOM_XPUV4,y)
endif

# TME-Lite communication stack. The tmel_com client reaches TME-Lite over the
# QMP-Lite mailbox channel, so pull the mailbox framework in with it.
CFG_QCOM_TMEL_COM ?= y
ifeq ($(CFG_QCOM_TMEL_COM),y)
$(call force,CFG_QCOM_MBOX,y,required by CFG_QCOM_TMEL_COM)
$(call force,CFG_QCOM_MBOX_QMP_LITE,y,required by CFG_QCOM_TMEL_COM)
endif

# Reserve carveout at the end of TZDRAM for the TMEL IPC coherent buffers.
CFG_TMECOM_IPCBUF_CARVEOUT_SIZE ?= 0x3000

# Hardware Unique Key provider (derives the HUK via TME-Lite KM).
# Enabling HUK forces the KM client on, since the HUK is its consumer.
CFG_QCOM_TMEL_HUK ?= y
ifeq ($(CFG_QCOM_TMEL_HUK),y)
$(call force,CFG_QCOM_TMEL_KM,y,required by CFG_QCOM_TMEL_HUK)
endif

# TME-Lite Key Management client (depends on the COM stack)
$(eval $(call cfg-depends-all,CFG_QCOM_TMEL_KM,CFG_QCOM_TMEL_COM))

# The HUK provider is a consumer of the KM client, so it has to follow it down
# when the COM stack is disabled.
$(eval $(call cfg-depends-all,CFG_QCOM_TMEL_HUK,CFG_QCOM_TMEL_KM))

# TME-Lite RNG client (depends on the COM stack)
$(eval $(call cfg-depends-all,CFG_QCOM_TMEL_RNG,CFG_QCOM_TMEL_COM))
