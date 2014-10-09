CROSS_PREFIX	?= armv7-linux
CROSS_COMPILE	?= $(CROSS_PREFIX)-
include mk/gcc.mk

PLATFORM_FLAVOR ?= orly2

platform-cpuarch = cortex-a9
platform-cflags	 = -mcpu=$(platform-cpuarch) -mthumb
platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
platform-cflags += -fno-short-enums -mno-apcs-float -fno-common
platform-aflags	 = -mcpu=$(platform-cpuarch)
core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-cppflags	+= -DNUM_THREADS=2
core-platform-cppflags	+= -DWITH_STACK_CANARIES=1
user_ta-platform-cflags = -fpie

DEBUG		?= 1
ifeq ($(DEBUG),1)
platform-cflags += -O0
else
platform-cflags += -Os
endif
platform-cflags += -g
platform-aflags += -g

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm sm tee sta) $(platform-dir)

libutil_with_isoc := y
WITH_PL310 := y
WITH_SECURE_TIME_SOURCE_REE := y

include mk/config.mk
include $(platform-dir)/system_config.in

ifndef CFG_TEE_CORE_NB_CORE
$(error "CFG_TEE_CORE_NB_CORE should be set from system_config.in")
endif
core-platform-cppflags += -DCFG_TEE_CORE_NB_CORE=$(CFG_TEE_CORE_NB_CORE)
core-cppflags += -DCFG_TEE_CORE_NB_CORE=$(CFG_TEE_CORE_NB_CORE)

ifndef CFG_TEE_CORE_EMBED_INTERNAL_TESTS
$(error "CFG_TEE_CORE_EMBED_INTERNAL_TESTS should be set from system_config.in")
endif
core-platform-cppflags += \
	-DCFG_TEE_CORE_EMBED_INTERNAL_TESTS=$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS)

ifndef CFG_DDR_TEETZ_RESERVED_START
$(error "CFG_DDR_TEETZ_RESERVED_START should be set from system_config.in")
endif
ifndef CFG_DDR_TEETZ_RESERVED_SIZE
$(error "CFG_DDR_TEETZ_RESERVED_SIZE should be set from system_config.in")
endif
core-platform-cppflags += \
	-DCFG_DDR_TEETZ_RESERVED_START=$(CFG_DDR_TEETZ_RESERVED_START) \
	-DCFG_DDR_TEETZ_RESERVED_SIZE=$(CFG_DDR_TEETZ_RESERVED_SIZE)


core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
core-platform-cppflags += -DCFG_NO_TA_HASH_SIGN

ifndef STACK_TMP_SIZE
$(error "STACK_TMP_SIZE should be set from system_config.in")
endif
ifndef STACK_ABT_SIZE
$(error "STACK_ABT_SIZE should be set from system_config.in")
endif
ifndef STACK_THREAD_SIZE
$(error "STACK_THREAD_SIZE should be set from system_config.in")
endif
core-platform-cppflags += -DSTACK_TMP_SIZE=$(STACK_TMP_SIZE)
core-platform-cppflags += -DSTACK_ABT_SIZE=$(STACK_ABT_SIZE)
core-platform-cppflags += -DSTACK_THREAD_SIZE=$(STACK_THREAD_SIZE)

ifdef DDR_PHYS_START
core-platform-cppflags += -DCFG_DDR_START=$(DDR_PHYS_START)
core-platform-cppflags += -DCFG_DDR_SIZE=$(DDR_SIZE)
endif
ifdef DDR1_PHYS_START
core-platform-cppflags += -DCFG_DDR1_START=$(DDR1_PHYS_START)
core-platform-cppflags += -DCFG_DDR1_SIZE=$(DDR1_SIZE)
endif

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
