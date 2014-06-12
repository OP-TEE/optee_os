CROSS_PREFIX	?= armv7-linux
CROSS_COMPILE	?= $(CROSS_PREFIX)-
include mk/gcc.mk

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

include mk/config.mk
include $(platform-dir)/system_config.in

core-platform-cppflags += -DCFG_TEE_CORE_NB_CORE=$(CFG_TEE_CORE_NB_CORE)

CFG_TEE_CORE_EMBED_INTERNAL_TESTS?=1
core-platform-cppflags += \
	-DCFG_TEE_CORE_EMBED_INTERNAL_TESTS=$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS)

core-platform-cppflags += \
	-DCFG_DDR_TEETZ_RESERVED_START=$(CFG_DDR_TEETZ_RESERVED_START) \
	-DCFG_DDR_TEETZ_RESERVED_SIZE=$(CFG_DDR_TEETZ_RESERVED_SIZE)

core-platform-cppflags += -DTEE_USE_DLMALLOC
core-platform-cppflags += -D_USE_SLAPORT_LIB


# define flag to support booting from GDB
core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
core-platform-cppflags += -DCFG_NO_TA_HASH_SIGN

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


PRIMARY_STARTUP_PHYS	 = \
	0x$(shell grep stext $(platform-dir)/System.map | grep -v _stext | \
		cut -d' ' -f 1)
SECONDARY_STARTUP_PHYS	 = \
	0x$(shell grep stm_secondary_startup $(platform-dir)/System.map | \
		cut -d' ' -f 1)
