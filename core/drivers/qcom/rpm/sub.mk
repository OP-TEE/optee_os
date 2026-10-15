# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-y += rpm_client.c
srcs-$(CFG_QCOM_RPM_TRANSPORT_STUB) += rpm_transport_stub.c
