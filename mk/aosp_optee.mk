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
OPTEE_OUT_DIR ?= $(PRODUCT_OUT)/optee
OPTEE_TA_OUT_DIR ?= $(OPTEE_OUT_DIR)/ta
# Set so that OP-TEE clients can find the installed dev-kit, which
# depends on platform and its OP-TEE word-size.
OPTEE_OS_OUT_DIR ?= $(OPTEE_OUT_DIR)/arm-plat-$(OPTEE_PLATFORM)
TA_DEV_KIT_DIR := $(OPTEE_OS_OUT_DIR)/export-${OPTEE_TA_TARGETS}

TOP_ROOT_ABS := $(realpath $(TOP))
CROSS_COMPILE64 := $(TOP_ROOT_ABS)/$(TARGET_TOOLS_PREFIX)
CROSS_COMPILE_LINE := CROSS_COMPILE64="$(CROSS_COMPILE64)"
ifeq ($(strip $($(combo_2nd_arch_prefix)TARGET_TOOLS_PREFIX)),)
CROSS_COMPILE32 := $(TOP_ROOT_ABS)/$($(combo_2nd_arch_prefix)TARGET_TOOLS_PREFIX)
CROSS_COMPILE_LINE += CROSS_COMPILE32="$(CROSS_COMPILE32)"
endif

##########################################################
## define BUILD_OPTEE_OS target, add condition check    ##
## to make it only be defined once even though          ##
## this file might be included multiple times           ##
##########################################################
ifneq (true,$(BUILD_OPTEE_OS_DEFINED))
BUILD_OPTEE_OS_DEFINED := true

.PHONY: BUILD_OPTEE_OS
BUILD_OPTEE_OS:
	@echo "Start building optee_os..."
	$(MAKE) -C $(TOP_ROOT_ABS)/$(OPTEE_OS_DIR) \
		O=$(TOP_ROOT_ABS)/$(OPTEE_OS_OUT_DIR) \
		ta-targets=$(OPTEE_TA_TARGETS) \
		CFG_ARM64_core=$(OPTEE_CFG_ARM64_CORE) \
		PLATFORM=$(OPTEE_PLATFORM) \
		PLATFORM_FLAVOR=$(OPTEE_PLATFORM_FLAVOR) \
		$(CROSS_COMPILE_LINE) \
		$(OPTEE_EXTRA_FLAGS)
	@echo "Finished building optee_os..."

endif

##########################################################
## Lines for building TAs automatically                 ##
## will only be included in Android.mk for TAs          ##
## local_module:                                        ##
##     need to be defined before include for this       ##
##########################################################
ifneq (false,$(INCLUDE_FOR_BUILD_TA))
include $(CLEAR_VARS)

LOCAL_MODULE := $(local_module)
LOCAL_PREBUILT_MODULE_FILE := $(OPTEE_TA_OUT_DIR)/$(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(TARGET_OUT)/lib/optee_armtz
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_TAGS := optional

TA_TMP_DIR := $(subst /,_,$(LOCAL_PATH))
TA_TMP_FILE := $(OPTEE_TA_OUT_DIR)/$(TA_TMP_DIR)/$(LOCAL_MODULE)
$(LOCAL_PREBUILT_MODULE_FILE): $(TA_TMP_FILE)
	@mkdir -p $(dir $@)
	cp -uvf $< $@

$(TA_TMP_FILE): PRIVATE_TA_SRC_DIR := $(LOCAL_PATH)
$(TA_TMP_FILE): PRIVATE_TA_TMP_FILE := $(TA_TMP_FILE)
$(TA_TMP_FILE): PRIVATE_TA_TMP_DIR := $(TA_TMP_DIR)
$(TA_TMP_FILE): BUILD_OPTEE_OS
	@echo "Start building TA for $(PRIVATE_TA_SRC_DIR) $(PRIVATE_TA_TMP_FILE)..."
	$(MAKE) -C $(TOP_ROOT_ABS)/$(PRIVATE_TA_SRC_DIR) O=$(TOP_ROOT_ABS)/$(OPTEE_TA_OUT_DIR)/$(PRIVATE_TA_TMP_DIR) \
		TA_DEV_KIT_DIR=$(TOP_ROOT_ABS)/$(TA_DEV_KIT_DIR) \
		$(CROSS_COMPILE_LINE)
	@echo "Finished building TA for $(PRIVATE_TA_SRC_DIR) $(PRIVATE_TA_TMP_FILE)..."

include $(BUILD_PREBUILT)
endif
