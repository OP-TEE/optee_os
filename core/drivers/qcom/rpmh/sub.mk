# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# RPMH (Resource Power Manager Hardened) Driver

# Core RPMH client API
srcs-y += rpmh_client.c

# RPMH hardware abstraction layer
srcs-y += rpmh_hal.c

global-incdirs-y += $(PLATFORM_FLAVOR)
