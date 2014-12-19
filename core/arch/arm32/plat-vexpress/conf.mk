CROSS_PREFIX	?= arm-linux-gnueabihf
CROSS_COMPILE	?= $(CROSS_PREFIX)-
include mk/gcc.mk

PLATFORM_FLAVOR ?= fvp
PLATFORM_FLAVOR_$(PLATFORM_FLAVOR) := y

platform-cpuarch = cortex-a15
platform-cflags	 = -mcpu=$(platform-cpuarch) -mthumb
platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
platform-cflags += -fno-short-enums -mno-apcs-float -fno-common
platform-cflags += -mfloat-abi=soft
platform-cflags += -mno-unaligned-access
platform-aflags	 = -mcpu=$(platform-cpuarch)
core-platform-cppflags	 = -I$(arch-dir)/include
core-platform-cppflags	+= -DNUM_THREADS=2
core-platform-cppflags	+= -DWITH_STACK_CANARIES=1
user_ta-platform-cflags = -fpie

platform-cflags += -ffunction-sections -fdata-sections

DEBUG		?= 1
ifeq ($(DEBUG),1)
platform-cflags += -O0
else
platform-cflags += -Os
endif

platform-cflags += -g
platform-aflags += -g

ifeq ($(PLATFORM_FLAVOR),fvp)
platform-flavor-armv8 := 1
endif
ifeq ($(PLATFORM_FLAVOR),juno)
platform-flavor-armv8 := 1
endif

ifeq ($(platform-flavor-armv8),1)
# ARM debugger needs this
platform-cflags += -gdwarf-2
platform-aflags += -gdwarf-2
else
platform-cflags += -g3
platform-aflags += -g3
endif

core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)
ifeq ($(platform-flavor-armv8),1)
core-platform-cppflags += -DWITH_ARM_TRUSTED_FW=1
else
core-platform-subdirs += $(arch-dir)/sm
core-platform-cppflags += -DWITH_SEC_MON=1
endif

CFG_PM_DEBUG ?= n

libutil_with_isoc := y
libtomcrypt_with_optimize_size := y
WITH_SECURE_TIME_SOURCE_CNTPCT := y
WITH_UART_DRV := y
WITH_GIC_DRV := y

include mk/config.mk

CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= 1

core-platform-cppflags += -D_USE_SLAPORT_LIB


# Several CPU suppoorted
core-platform-cppflags += -DTEE_MULTI_CPU
# define flag to support booting from GDB
core-platform-cppflags += -DCONFIG_TEE_GDB_BOOT
CFG_NO_TA_HASH_SIGN ?= y

core-platform-cppflags += -DWITH_UART_DRV=1
