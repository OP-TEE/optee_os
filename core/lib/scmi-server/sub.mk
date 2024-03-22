# SCMI server library is built from SCP-firmware source tree.
# The firmware is made of a framework, a product and modules.
# Only modules used by firmware must be built, as stated by
# CFG_SCPFW_MOD_* switches. SCP-firmware needs a C source and
# a header file to be generated to describe embedded modules.
# This is done through cmake configuration of the package.
# The toolchain build directive must also match the list of
# embedded modules.

scpfw-path = $(CFG_SCP_FIRMWARE)
scpfw-product = optee/$(CFG_SCMI_SCPFW_PRODUCT)
scpfw-out-path := $(out-dir)/$(libdir)

scpfw-integ-version-maj = 2
scpfw-integ-version-min = 14
scpfw-integ-version-pat = 0
scpfw-integ-version = $(scpfw-integ-version-maj).$(scpfw-integ-version-min).$(scpfw-integ-version-pat)

srcs-y += scmi_server.c
incdirs-y += include

# SCP-firmware cmake configuration generates header fwk_module_idx.h and
# source files fwk_module_list.c needed for scp-firmware compilation.
scpfw-cmake-flags-y = -DSCP_FIRMWARE_SOURCE_DIR:PATH=$(scpfw-product)/fw \
		      -DSCP_LOG_LEVEL="TRACE" \
		      -DDISABLE_CPPCHECK=1 \
		      -DCFG_NUM_THREADS=$(CFG_NUM_THREADS) \
		      -DSCP_OPTEE_DIR:PATH=$(CURDIR)

# CMake does not need to check the cross compilation toolchain since we do not
# compile any source file with CMake, we only generate some SCP-firmware
# files.
scpfw-cmake-flags-y += -DCMAKE_C_COMPILER_WORKS=1

ifeq ($(cmd-echo-silent),true)
scpfw-cmake-redirect = >/dev/null
endif

gensrcs-y += fwk_module_list
force-gensrc-fwk_module_list := y
produce-fwk_module_list = build/framework/src/fwk_module_list.c
recipe-fwk_module_list = cmake -S $(scpfw-path) -B $(scpfw-out-path)/build \
                         $(scpfw-cmake-flags-y) --log-level=WARNING $(scpfw-cmake-redirect)
depends-fwk_module_list = $(scpfw-path)/product/$(scpfw-product)/fw/Firmware.cmake $(conf-file)
# Include path of generated header file fwk_module_idx.h
incdirs_ext-y += $(scpfw-out-path)/build/framework/include

cppflags-lib-y += -DBUILD_VERSION_MAJOR=$(scpfw-integ-version-maj) \
		  -DBUILD_VERSION_MINOR=$(scpfw-integ-version-min) \
		  -DBUILD_VERSION_PATCH=$(scpfw-integ-version-pat)

scpfw-impl-version := $(shell git -C $(scpfw-path) describe --tags --always --dirty=-dev 2>/dev/null || \
                      echo Unknown_$(scpfw-integ-version))
cppflags-lib-y += -DBUILD_VERSION_DESCRIBE_STRING=\"$(scpfw-impl-version)\"

cppflags-lib-y += -DFWK_LOG_LEVEL=$(CFG_SCPFW_LOG_LEVEL)
ifneq ($(CFG_SCPFW_LOG_LEVEL),0)
cppflags-lib-y += -DFMW_LOG_MINIMAL_BANNER=1
endif

cflags-lib-y += -Wno-cast-align \
		-Wno-nonnull-compare \
		-Wno-unused-parameter \
		-Wno-suggest-attribute=format \
		-Wno-declaration-after-statement

# The below directives will be removed once SCP-firmware pull requests
# 728 and 732 are merged.
cflags-lib-y += -Wno-undef \
		-Wno-missing-prototypes \
		-Wno-missing-declarations \
		-Wno-unused-but-set-variable \
		-Wno-suggest-attribute=format

# Notification implementation has strict aliasing issues
cflags-lib-$(CFG_SCPFW_NOTIFICATION) += -Wno-strict-aliasing

cppflags-lib-y += -DBUILD_HAS_SUB_SYSTEM_MODE=1 \
		  -DBUILD_HAS_BASE_PROTOCOL

cppflags-lib-$(CFG_SCPFW_NOTIFICATION) += -DBUILD_HAS_NOTIFICATION \
					  -DBUILD_HAS_SCMI_NOTIFICATIONS

cppflags-lib-$(CFG_SCPFW_FAST_CHANNELS) += -DBUILD_HAS_FAST_CHANNELS \
					   -DBUILD_HAS_SCMI_FAST_CHANNELS

cppflags-lib-$(CFG_SCPFW_CLOCK_TREE_MGMT) += -DBUILD_HAS_CLOCK_TREE_MGMT

cppflags-lib-$(CFG_SCPFW_SCMI_PERF_FAST_CHANNELS) += -DBUILD_HAS_SCMI_PERF_FAST_CHANNELS

cppflags-lib-$(CFG_SCPFW_SCMI_PERF_PROTOCOL_OPS) \
	+= -DBUILD_HAS_SCMI_PERF_PROTOCOL_OPS

cppflags-lib-$(CFG_SCPFW_SCMI_SENSOR_EVENTS) += -DBUILD_HAS_SCMI_SENSOR_EVENTS
cppflags-lib-$(CFG_SCPFW_SCMI_SENSOR_V2) += -DBUILD_HAS_SCMI_SENSOR_V2 \
					    -DBUILD_HAS_SENSOR_TIMESTAMP \
					    -DBUILD_HAS_SENSOR_MULTI_AXIS \
					    -DBUILD_HAS_SENSOR_EXT_ATTRIBS \
					    -DBUILD_HAS_SENSOR_SIGNED_VALUE

cppflags-lib-$(CFG_SCPFW_SENSOR_TIMESTAMP) += -DBUILD_HAS_SENSOR_TIMESTAMP
cppflags-lib-$(CFG_SCPFW_SENSOR_MULTI_AXIS) += -DBUILD_HAS_SENSOR_MULTI_AXI
cppflags-lib-$(CFG_SCPFW_SENSOR_EXT_ATTRIBS) += -DBUILD_HAS_SENSOR_EXT_ATTRIBS
cppflags-lib-$(CFG_SCPFW_SENSOR_SIGNED_VALUE) += -DBUILD_HAS_SENSOR_SIGNED_VALUE
cppflags-lib-$(CFG_SCPFW_INBAND_MSG_SUPPORT) += -DBUILD_HAS_INBAND_MSG_SUPPORT

# Include SCP-firmware make files
include $(scpfw-path)/product/optee/sub.mk

