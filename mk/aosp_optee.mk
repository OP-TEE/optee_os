##########################################################
## Common mk file used for Android to compile and       ##
## integrate OP-TEE related components                  ##
## Following flags need to be defined in optee*.mk      ##
##    OPTEE_OS_DIR                                      ##
##    OPTEE_TA_TARGETS                                  ##
##    OPTEE_CFG_ARM64_CORE                              ##
##    OPTEE_PLATFORM                                    ##
##    OPTEE_PLATFORM_FLAVOR                             ##
##    OPTEE_EXTRA_FLAGS (optional)                      ##
##    OPTEE_EXTRA_TA_FLAGS (optional)                   ##
## And BUILD_OPTEE_MK needs to be defined in optee*.mk  ##
## to point to this file                                ##
##                                                      ##
## local_module needs to be defined before including    ##
## this file to build TAs                               ##
##                                                      ##
##########################################################

##########################################################
## define common variables, like TA_DEV_KIT_DIR         ##
##########################################################
TOP_ROOT_ABS := $(realpath $(TOP))

PREBUILT_MAKE ?= prebuilts/build-tools/linux-x86/bin/make
# we need this check because the Pie build does not have
# this prebuilt make tool
ifneq (,$(wildcard $(PREBUILT_MAKE)))
# for master and versions which has prebuilt make
HOST_MAKE := $(PREBUILT_MAKE)

# The AOSP build tool is not the regular make,
# that it adds -jN to $(MAKE), and that we should preserve
# the flag or we would lose parallel build
# The MAKE is redefined here in AOSP ckati:
#   https://android.googlesource.com/platform/build/kati/+/master/main.cc#100
ifneq (,$(filter -j%, $(MAKE)))
HOST_MAKE += $(filter -j%, $(MAKE))
endif

else
# For P and old versions which does not have prebuilt make,
# let's use MAKE as what we did before
HOST_MAKE := $(MAKE)
endif


# OPTEE_OUT_DIR could be exported explicitly
# if PRODUCT_OUT is not the default out directory in aosp workspace
OPTEE_OUT_DIR ?= $(PRODUCT_OUT)/optee
ABS_OPTEE_OUT_DIR ?= $(realpath $(PRODUCT_OUT))/optee
OPTEE_TA_OUT_DIR ?= $(OPTEE_OUT_DIR)/ta
ABS_OPTEE_TA_OUT_DIR ?= $(ABS_OPTEE_OUT_DIR)/ta
# Set so that OP-TEE clients can find the installed dev-kit, which
# depends on platform and its OP-TEE word-size.
OPTEE_OS_OUT_DIR ?= $(OPTEE_OUT_DIR)/arm-plat-$(OPTEE_PLATFORM)
ABS_OPTEE_OS_OUT_DIR := $(ABS_OPTEE_OUT_DIR)/arm-plat-$(OPTEE_PLATFORM)
ifneq ($(local_optee_ta_target),)
TA_TARGET := $(local_optee_ta_target)
else
TA_TARGET := $(OPTEE_TA_TARGETS)
endif
TA_DEV_KIT_DIR := $(OPTEE_OS_OUT_DIR)/export-$(TA_TARGET)
ABS_TA_DEV_KIT_DIR := $(ABS_OPTEE_OS_OUT_DIR)/export-$(TA_TARGET)

CROSS_COMPILE64 ?= $(TOP_ROOT_ABS)/$(TARGET_TOOLS_PREFIX)
CROSS_COMPILE_LINE := CROSS_COMPILE64="$(CROSS_COMPILE64)"
ifneq ($(strip $($(combo_2nd_arch_prefix)TARGET_TOOLS_PREFIX)),)
CROSS_COMPILE32 ?= $(TOP_ROOT_ABS)/$($(combo_2nd_arch_prefix)TARGET_TOOLS_PREFIX)
CROSS_COMPILE_LINE += CROSS_COMPILE32="$(CROSS_COMPILE32)"
endif

OPTEE_BIN := $(OPTEE_OS_OUT_DIR)/core/tee.bin

$(OPTEE_BIN) : $(sort $(shell find -L $(OPTEE_OS_DIR)))

OPTEE_TA_DEV_KIT_MK := $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

$(OPTEE_TA_DEV_KIT_MK) : $(sort $(shell find -L $(OPTEE_OS_DIR)))

###########################################################
## define making rules for $(OPTEE_BIN) target, and add  ##
## condition check to make it only be defined once       ##
## even though this mk file might be included multiple   ##
## times. The process to generate $(OPTEE_BIN) file will ##
## generate the header files under                       ##
## $(TA_DEV_KIT_DIR)/host_include too.                   ##
## And the $(OPTEE_BIN) will be used as dependency for   ##
## other projects                                        ##
###########################################################
ifneq (true,$(BUILD_OPTEE_OS_DEFINED))
BUILD_OPTEE_OS_DEFINED := true
$(OPTEE_BIN):
	@echo "Start building optee_os..."
	+$(HOST_MAKE) -C $(TOP_ROOT_ABS)/$(OPTEE_OS_DIR) \
		O=$(ABS_OPTEE_OS_OUT_DIR) \
		CFG_USER_TA_TARGETS=$(OPTEE_TA_TARGETS) \
		CFG_ARM64_core=$(OPTEE_CFG_ARM64_CORE) \
		PLATFORM=$(OPTEE_PLATFORM) \
		PLATFORM_FLAVOR=$(OPTEE_PLATFORM_FLAVOR) \
		$(CROSS_COMPILE_LINE) \
		$(OPTEE_EXTRA_FLAGS)
	@echo "Finished building optee_os..."

endif

###########################################################
## similar to the $(OPTEE_BIN) target above, use condition
## check to make $(OPTEE_TA_DEV_KIT_MK) for different ta
## targets only be defined once
###########################################################
ifeq ($(filter $(TA_TARGET),$(BUILD_TA_DEV_KIT_DEFINED)),)
BUILD_TA_DEV_KIT_DEFINED := $(TA_TARGET) $(BUILD_TA_DEV_KIT_DEFINED)
$(OPTEE_TA_DEV_KIT_MK): PRIVATE_TA_TARGET := $(TA_TARGET)
$(OPTEE_TA_DEV_KIT_MK):
	@echo "Start building ta_dev_kit ($(PRIVATE_TA_TARGET))..."
	+$(HOST_MAKE) -C $(TOP_ROOT_ABS)/$(OPTEE_OS_DIR) \
		O=$(ABS_OPTEE_OS_OUT_DIR) \
		CFG_USER_TA_TARGETS=$(PRIVATE_TA_TARGET) \
		CFG_ARM64_core=$(OPTEE_CFG_ARM64_CORE) \
		PLATFORM=$(OPTEE_PLATFORM) \
		PLATFORM_FLAVOR=$(OPTEE_PLATFORM_FLAVOR) \
		$(CROSS_COMPILE_LINE) \
		$(OPTEE_EXTRA_FLAGS) ta_dev_kit
	@echo "Finished building ta_dev_kit ($(PRIVATE_TA_TARGET))..."
endif

##########################################################
## Lines for building TAs automatically                 ##
## will only be included in Android.mk for TAs          ##
## local_module:                                        ##
##     need to be defined before include for this       ##
##########################################################
ifneq (false,$(INCLUDE_FOR_BUILD_TA))
include $(CLEAR_VARS)

define ta_class
$(if $(filter %.ta,$1),EXECUTABLES,STATIC_LIBRARIES)
endef

LOCAL_MODULE := $(local_module)
LOCAL_PREBUILT_MODULE_FILE := $(OPTEE_TA_OUT_DIR)/$(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/lib/optee_armtz
LOCAL_MODULE_CLASS := $(call ta_class,$(local_module))
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := $(local_module_deps)

TA_TMP_DIR := $(addsuffix _$(TA_TARGET), $(subst /,_,$(LOCAL_PATH)))
TA_TMP_FILE := $(OPTEE_TA_OUT_DIR)/$(TA_TMP_DIR)/$(LOCAL_MODULE)
$(LOCAL_PREBUILT_MODULE_FILE): $(TA_TMP_FILE)
	@mkdir -p $(dir $@)
	cp -vf $< $@

TA_TMP_FILE_DEPS :=
ifneq ($(local_module_deps),)
$(foreach dep, $(local_module_deps), $(eval TA_TMP_FILE_DEPS += $(call intermediates-dir-for,$(call ta_class,$(dep)),$(dep))/$(dep)))
endif
$(TA_TMP_FILE): $(TA_TMP_FILE_DEPS)
$(TA_TMP_FILE): PRIVATE_TA_SRC_DIR := $(LOCAL_PATH)
$(TA_TMP_FILE): PRIVATE_TA_TMP_FILE := $(TA_TMP_FILE)
$(TA_TMP_FILE): PRIVATE_TA_TMP_DIR := $(TA_TMP_DIR)
$(TA_TMP_FILE): PRIVATE_TA_DEV_KIT_DIR := $(ABS_TA_DEV_KIT_DIR)
$(TA_TMP_FILE): $(OPTEE_TA_DEV_KIT_MK)
	@echo "Start building TA for $(PRIVATE_TA_SRC_DIR) $(PRIVATE_TA_TMP_FILE)..."
	+$(HOST_MAKE) -C $(TOP_ROOT_ABS)/$(PRIVATE_TA_SRC_DIR) O=$(ABS_OPTEE_TA_OUT_DIR)/$(PRIVATE_TA_TMP_DIR) \
		TA_DEV_KIT_DIR=$(PRIVATE_TA_DEV_KIT_DIR) \
		$(CROSS_COMPILE_LINE) \
		$(OPTEE_EXTRA_TA_FLAGS)
	@echo "Finished building TA for $(PRIVATE_TA_SRC_DIR) $(PRIVATE_TA_TMP_FILE)..."

include $(BUILD_PREBUILT)

# To get ta elf files for early-ta,
# copy them to $(PRODUCT_OUT)/unsigned/ on host
ifeq ($(call ta_class,$(local_module)),EXECUTABLES)
include $(CLEAR_VARS)
LOCAL_MODULE := $(local_module).unsigned
LOCAL_PREBUILT_MODULE_FILE := $(OPTEE_TA_OUT_DIR)/$(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/unsigned
LOCAL_MODULE_CLASS := $(call ta_class,$(local_module))
LOCAL_MODULE_TAGS := optional

TA_TMP_STRIPPED_ELF_FILE := $(patsubst %.ta,%.stripped.elf,$(TA_TMP_FILE))
$(TA_TMP_STRIPPED_ELF_FILE): $(TA_TMP_FILE)

$(LOCAL_PREBUILT_MODULE_FILE): $(TA_TMP_STRIPPED_ELF_FILE)
	@mkdir -p $(dir $@)
	cp -vf $< $@

include $(BUILD_PREBUILT)
endif  # to get ta elf files for early-ta

local_module_deps :=
local_optee_ta_target :=
endif
