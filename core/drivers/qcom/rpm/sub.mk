# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# Classic RPM (Resource Power Manager) client driver.
#

srcs-y += rpm_client.c
srcs-y += rpm_hal.c
srcs-y += kvp.c

global-incdirs-y += $(QCOM_ARCH_FAMILY)
global-incdirs-y += .
