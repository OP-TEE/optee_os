# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# RPMH (Resource Power Manager Hardened) Driver

# Core RPMH client API
srcs-y += rpmh_client.c

# RPMH hardware abstraction layer
srcs-y += rpmh_hal.c

# TCS (Task Control Structure) management
srcs-y += rpmh_tcs.c

# Resource command tracking and management
srcs-y += rpmh_resource_commands.c

# DRV configuration
srcs-y += rpmh_drv_config.c
