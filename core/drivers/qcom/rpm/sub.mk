# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# Classic RPM (Resource Power Manager) client driver.
#

srcs-y += rpm_client.c
srcs-y += rpm_hal.c
srcs-y += kvp.c
srcs-y += glink/rpm_glink.c
srcs-$(CFG_QCOM_RPM_TRANSPORT_GLINK) += rpm_transport_glink.c
srcs-$(CFG_QCOM_RPM_TRANSPORT_STUB)  += rpm_transport_stub.c

ifeq ($(CFG_QCOM_RPM_TRANSPORT_GLINK)-$(CFG_QCOM_RPM_TRANSPORT_STUB),y-y)
$(error CFG_QCOM_RPM_TRANSPORT_GLINK and CFG_QCOM_RPM_TRANSPORT_STUB are mutually exclusive)
endif

global-incdirs-y += $(QCOM_ARCH_FAMILY)
global-incdirs-y += glink
global-incdirs-y += .
