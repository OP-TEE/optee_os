# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
#

srcs-$(CFG_QCOM_RAMBLUR_PIMEM_V3) += ramblur/ramblur_pimem_v3.c
srcs-$(CFG_QCOM_RNG) += rng/qcom-rng.c
srcs-$(CFG_QCOM_SEC_WDOG) += wdt/wdt.c

$(eval $(call cfg-depends-all,CFG_QCOM_QFPROM,CFG_QCOM_CMD_DB CFG_QCOM_RPMH_CLIENT))
$(eval $(call cfg-depends-all,CFG_QCOM_RPMH_CLIENT,CFG_QCOM_CMD_DB))
subdirs-$(CFG_QCOM_CMD_DB) += cmd_db
subdirs-$(CFG_QCOM_RPMH_CLIENT) += rpmh
subdirs-$(CFG_QCOM_QFPROM) += qfprom
