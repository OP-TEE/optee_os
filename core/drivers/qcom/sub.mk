# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
#

ifeq ($(CFG_QCOM_RAMBLUR_PIMEM_V3),y)
srcs-y += ramblur/ramblur_pimem_v3.c
ifeq ($(CFG_EMBED_DTB),y)
srcs-y += ramblur/ramblur_pimem_cfg_dt.c
else
srcs-y += ramblur/ramblur_pimem_cfg_non_dt.c
endif
endif
srcs-$(CFG_QCOM_CSRNG) += rng/qcom-csrng.c
srcs-$(CFG_QCOM_SEC_WDOG) += wdt/qcom-wdt.c

subdirs-$(CFG_QCOM_CMD_DB) += cmd_db
subdirs-$(CFG_QCOM_RPMH_CLIENT) += rpmh
subdirs-$(CFG_QCOM_QFPROM) += qfprom
subdirs-$(CFG_QCOM_XPUV4) += xpu
subdirs-$(CFG_QCOM_TLMM) += tlmm
