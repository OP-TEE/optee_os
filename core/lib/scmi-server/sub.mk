# SCMI server library is built from SCP-firmware source tree.
# The firmware is made of a framework, a product and modules.
# Only modules used by firmware must be built, as stated by
# CFG_SCPFW_MOD_* swtches. SCP-firmware needs a C source and
# a header file to be generated to describe embedded modules.
# This is done through cmake configuration of the package.
# The toolchain build directive must also match the list of
# embedded modules.

scpfw-path = $(CFG_SCP_FIRMWARE)
scpfw-product = $(CFG_SCMI_SCPFW_PRODUCT)
scpfw-out-path := $(out-dir)/$(libdir)

# This script was validated against SCP-firmware 2.11.0 development branch,
# from commit f1d894921d76 ("product/optee-fvp: Add new OPTEE FVP product").
scpfw-integ-version-maj = 2
scpfw-integ-version-min = 11
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
		      -DSCP_OPTEE_DIR:PATH=$(CURDIR) \
		      -DCFG_CROSS_COMPILE=$(lastword $(CROSS_COMPILE_core))

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

incdirs_ext-y += $(scpfw-path)/arch/none/optee/include
srcs-y += $(scpfw-path)/arch/none/optee/src/arch_interrupt.c
srcs-y += $(scpfw-path)/arch/none/optee/src/arch_main.c

incdirs_ext-y += $(scpfw-path)/framework/include
srcs-y += $(scpfw-path)/framework/src/fwk_arch.c
srcs-y += $(scpfw-path)/framework/src/fwk_dlist.c
srcs-y += $(scpfw-path)/framework/src/fwk_id.c
srcs-y += $(scpfw-path)/framework/src/fwk_interrupt.c
srcs-y += $(scpfw-path)/framework/src/fwk_io.c
srcs-y += $(scpfw-path)/framework/src/fwk_log.c
srcs-y += $(scpfw-path)/framework/src/fwk_mm.c
srcs-y += $(scpfw-path)/framework/src/fwk_module.c
srcs-y += $(scpfw-path)/framework/src/fwk_ring.c
srcs-y += $(scpfw-path)/framework/src/fwk_slist.c
srcs-y += $(scpfw-path)/framework/src/fwk_status.c
srcs-y += $(scpfw-path)/framework/src/fwk_string.c
srcs-y += $(scpfw-path)/framework/src/fwk_delayed_resp.c
srcs-y += $(scpfw-path)/framework/src/fwk_time.c
srcs-y += $(scpfw-path)/framework/src/fwk_core.c
srcs-y += $(scpfw-path)/framework/src/assert.c
srcs-y += $(scpfw-path)/framework/src/stdlib.c
srcs-$(CFG_SCPFW_NOTIFICATION) += $(scpfw-path)/framework/src/fwk_notification.c

# Helper macros for listing SCP-firmware modules source files (in srcs-y)
# and header include paths (in incdirs_ext-y). Each module provides a C source
# file named mod_<module-name>.c and possibly an include directory. Build
# directive BUILD_HAS_MOD_<NAME> must be set for each embedded module.
#
# Standard modules source tree: <scp-path>/module/<name>/src/mod_<name>.c
# Optee modules source tree:    <scp-path>/module/optee/<short-name>/src/mod_<name>.c
# Product modules source tree:  <scp-path>/product/<product-name>/module/<name>/src/mod_<name>.c
#
# scpfw-embed-generic-module is to be used for standard modules.
# scpfw-embed-optee-module is to be used for optee modules.
# scpfw-embed-product-module is to be used for product modules.
# For modules that implement other C source files aside mandatory mod_<name>.c we must
# add to srcs-y the required source file paths.
#
# scpfw-embed-mod takes 4 arguments:
# $1 module name, lowercase
# $2 module directory name
# $3 module parent directory relative path in scpfw tree
# $4 module name, uppercase, relates to CFG_SCPFW_MOD_$4
define scpfw-embed-mod
ifneq (,$$(wildcard $(scpfw-path)/$3/$2/include/*))
incdirs_ext-y += $(scpfw-path)/$3/$2/include
endif
srcs-$(CFG_SCPFW_MOD_$4) += $(scpfw-path)/$3/$2/src/mod_$1.c

# SCMI_Perf in SCP-firmware has components that can be added conditionally at
# build time.
ifeq ($(1), scmi_perf)

ifeq ($(CFG_SCPFW_SCMI_PERF_PROTOCOL_OPS),y)
srcs-$(CFG_SCPFW_MOD_SCMI_PERF) += $(scpfw-path)/$3/$2/src/scmi_perf_protocol_ops.c
endif

ifeq ($(CFG_SCPFW_SCMI_PERF_FAST_CHANNELS),y)
srcs-$(CFG_SCPFW_MOD_SCMI_PERF) += $(scpfw-path)/$3/$2/src/scmi_perf_fastchannels.c
endif

endif

cflags-lib-$(CFG_SCPFW_MOD_$4) += -DBUILD_HAS_MOD_$4
endef

define scpfw-embed-generic-module
$(eval $(call scpfw-embed-mod,$1,$1,module,$(shell echo $1 | tr a-z A-Z)))
endef

define scpfw-embed-optee-module
$(eval $(call scpfw-embed-mod,optee_$1,$1,module/optee,OPTEE_$(shell echo $1 | tr a-z A-Z)))
endef

define scpfw-embed-product-module
$(eval $(call scpfw-embed-mod,$1,$1,product/$(scpfw-product)/module,$(shell echo $1 | tr a-z A-Z)))
endef

$(eval $(call scpfw-embed-generic-module,clock))
$(eval $(call scpfw-embed-generic-module,dvfs))
$(eval $(call scpfw-embed-generic-module,mock_clock))
$(eval $(call scpfw-embed-generic-module,mock_ppu))
$(eval $(call scpfw-embed-generic-module,mock_psu))
$(eval $(call scpfw-embed-generic-module,msg_smt))
$(eval $(call scpfw-embed-generic-module,power_domain))
$(eval $(call scpfw-embed-generic-module,psu))
$(eval $(call scpfw-embed-generic-module,reg_sensor))
$(eval $(call scpfw-embed-generic-module,reset_domain))
$(eval $(call scpfw-embed-generic-module,sensor))
$(eval $(call scpfw-embed-generic-module,scmi))
$(eval $(call scpfw-embed-generic-module,scmi_apcore))
$(eval $(call scpfw-embed-generic-module,scmi_clock))
$(eval $(call scpfw-embed-generic-module,scmi_perf))
$(eval $(call scpfw-embed-generic-module,scmi_power_domain))
$(eval $(call scpfw-embed-generic-module,scmi_reset_domain))
$(eval $(call scpfw-embed-generic-module,scmi_sensor))
$(eval $(call scpfw-embed-generic-module,scmi_voltage_domain))
$(eval $(call scpfw-embed-generic-module,system_pll))
$(eval $(call scpfw-embed-generic-module,voltage_domain))
$(eval $(call scpfw-embed-optee-module,clock))
$(eval $(call scpfw-embed-optee-module,console))
$(eval $(call scpfw-embed-optee-module,mbx))
$(eval $(call scpfw-embed-optee-module,reset))
$(eval $(call scpfw-embed-optee-module,smt))

srcs-$(CFG_SCPFW_MOD_CLOCK) += $(scpfw-path)/module/clock/src/clock_tree_management.c
srcs-$(CFG_SCPFW_MOD_POWER_DOMAIN) += $(scpfw-path)/module/power_domain/src/power_domain_utils.c
srcs-$(CFG_SCPFW_MOD_SCMI) += $(scpfw-path)/module/scmi/src/mod_scmi_base.c
srcs-$(CFG_SCPFW_MOD_SCMI_SENSOR) += $(scpfw-path)/module/scmi_sensor/src/mod_scmi_ext_attrib.c
srcs-$(CFG_SCPFW_MOD_SENSOR) += $(scpfw-path)/module/sensor/src/sensor_extended.c

# Architecture arch/none/optee requires optee mbx header file
incdirs_ext-y += $(scpfw-path)/module/optee/mbx/include
# Some modules require header files from module that are not embedded
ifneq (,$(filter y, $(CFG_SCPFW_MOD_DVFS) $(CFG_SCPFW_MOD_MOCK_PSU) $(CFG_SCPFW_MOD_SCMI_PERF)))
incdirs_ext-y += $(scpfw-path)/module/timer/include
endif
incdirs_ext-$(CFG_SCPFW_MOD_OPTEE_MBX) += $(scpfw-path)/module/msg_smt/include
incdirs_ext-$(CFG_SCPFW_MOD_SCMI) += $(scpfw-path)/module/power_domain/include

include core/lib/scmi-server/sub-$(CFG_SCMI_SCPFW_PRODUCT).mk
