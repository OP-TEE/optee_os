include core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk

CROSS_PREFIX	?= armv7-linux
CROSS_COMPILE	?= $(CROSS_PREFIX)-
include mk/gcc.mk

core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-cppflags	+= -DNUM_THREADS=2


core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm sm tee sta) $(platform-dir)

libutil_with_isoc := y
WITH_PL310 := y
WITH_SECURE_TIME_SOURCE_REE := y
CFG_CACHE_API := y
CFG_WITH_STACK_CANARIES := y
CFG_WITH_SEC_MON := y

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

ifeq ($(PLATFORM_FLAVOR),cannes)

PRIMARY_STARTUP_PHYS	 = $(shell echo $$(( ${CFG_LINUX_LOAD_ADDR} + 0x8000 )))
OFFSET_STARTUP_PHYS	 = $(shell echo $$((\
 	$(PRIMARY_STARTUP_PHYS) - \
 	0x$(shell grep stext $(platform-dir)/System.map | grep -v _stext | \
 		cut -d' ' -f 1) )) )
SECONDARY_STARTUP_PHYS	 = $(shell echo $$((\
	0x$(shell grep sti_secondary_startup $(platform-dir)/System.map | \
		cut -d' ' -f 1) + $(OFFSET_STARTUP_PHYS) )) )

else ifeq ($(PLATFORM_FLAVOR),orly2)

PRIMARY_STARTUP_PHYS	 = \
	0x$(shell grep stext $(platform-dir)/System.map | grep -v _stext | \
		cut -d' ' -f 1)
SECONDARY_STARTUP_PHYS	 = \
	0x$(shell grep stm_secondary_startup $(platform-dir)/System.map | \
		cut -d' ' -f 1)
else
$(error PLATFORM_FLAVOR=$(PLATFORM_FLAVOR) is not supported)
endif

TEE_SCATTER_START=$(CFG_DDR_TEETZ_RESERVED_START)
export TEE_SCATTER_START
