# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# Private transport header
incdirs-y += ../tme_transport

srcs-y += tme_fuse_read.c
srcs-y += tme_fuse_write_multiple.c
srcs-y += tme_get_arb_version.c
srcs-y += tme_message.c
srcs-y += tme_update_rollback_version.c
srcs-y += tme_write_config_register.c
