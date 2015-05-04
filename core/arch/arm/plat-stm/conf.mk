include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_COMPILE	?= armv7-linux-
COMPILER	?= gcc

CFG_ARM32_core ?= y

core-platform-cppflags	 = -I$(arch-dir)/include

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm sm tee sta) $(platform-dir)

libutil_with_isoc := y
CFG_PL310 := y
CFG_SECURE_TIME_SOURCE_REE := y
CFG_CACHE_API := y
CFG_WITH_STACK_CANARIES := y
CFG_PM_STUBS := y

include mk/config.mk
include $(platform-dir)/system_config.in

ifndef CFG_TEE_CORE_EMBED_INTERNAL_TESTS
$(error "CFG_TEE_CORE_EMBED_INTERNAL_TESTS should be set from system_config.in")
endif

ifndef CFG_DDR_TEETZ_RESERVED_START
$(error "CFG_DDR_TEETZ_RESERVED_START should be set from system_config.in")
endif
ifndef CFG_DDR_TEETZ_RESERVED_SIZE
$(error "CFG_DDR_TEETZ_RESERVED_SIZE should be set from system_config.in")
endif

core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
CFG_NO_TA_HASH_SIGN ?= y

CFG_WITH_SOFTWARE_PRNG ?= n

grep-system-map = 0x$(firstword \
	$(shell grep -s $(1) $(platform-dir)/System.map || echo 0))

ifeq ($(PLATFORM_FLAVOR),cannes)

PRIMARY_STARTUP_PHYS	 = $(shell echo $$(( ${CFG_LINUX_LOAD_ADDR} + 0x8000 )))
OFFSET_STARTUP_PHYS	 = $(shell echo $$((\
	$(PRIMARY_STARTUP_PHYS) - \
	$(call grep-system-map,"[^_]stext") )) )
SECONDARY_STARTUP_PHYS	 = $(shell echo $$((\
	$(call grep-system-map,"sti_secondary_startup") + \
	$(OFFSET_STARTUP_PHYS) )) )

else ifeq ($(PLATFORM_FLAVOR),orly2)

PRIMARY_STARTUP_PHYS	 = $(call grep-system-map,"[^_]stext")
SECONDARY_STARTUP_PHYS	 = $(call grep-system-map,"stm_secondary_startup")
else
$(error PLATFORM_FLAVOR=$(PLATFORM_FLAVOR) is not supported)
endif

TEE_SCATTER_START=$(CFG_DDR_TEETZ_RESERVED_START)
export TEE_SCATTER_START
