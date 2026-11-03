# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# tme_transport.h is private to tme_intf, it is not a global include
incdirs-y += ../tme_transport

srcs-y += tme_fuse_read.c
srcs-y += tme_fuse_write_multiple.c
srcs-y += tme_message.c
srcs-y += tme_update_rollback_version.c
srcs-y += tme_write_config_register.c
