PLATFORM_FLAVOR ?= rcar
PLATFORM_FLAVOR_$(PLATFORM_FLAVOR) := y

ifneq ($(CFG_ARM64_core),y)
CFG_ARM32_core ?= y
endif

# 32-bit flags
arm32-platform-cpuarch	:= cortex-a15
arm32-platform-cflags	+= -mcpu=$(arm32-platform-cpuarch) -marm
arm32-platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
arm32-platform-cflags	+= -fno-short-enums -mno-apcs-float -fno-common
arm32-platform-cflags	+= -mfloat-abi=soft
arm32-platform-cflags	+= -mno-unaligned-access
arm32-platform-aflags	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags	+= -mfpu=neon

# 64-bit flags
arm64-platform-cflags	+= -mstrict-align

platform-cflags += -ffunction-sections -fdata-sections

DEBUG		?= 0
ifeq ($(DEBUG),1)
platform-cflags += -O0
else
platform-cflags += -Os
endif

platform-cflags += -g
platform-aflags += -g

platform-flavor-armv8 := 1

ifeq ($(platform-flavor-armv8),1)
# ARM debugger needs this
platform-cflags += -gdwarf-2
platform-aflags += -gdwarf-2
else
platform-cflags += -g3
platform-aflags += -g3
endif

CFG_ARM32_user_ta := y
user_ta-platform-cflags += $(arm32-platform-cflags)
user_ta-platform-cflags += -fpie
user_ta-platform-cppflags += $(arm32-platform-cppflags)
user_ta-platform-aflags += $(arm32-platform-aflags)

VERSION_OF_RENESAS ?= $(shell awk '/VERSION_OF_RENESAS/{ \
	$$a=substr($$3,2); sub(/.$$/,"",$$a); print $$a}' \
	< core/arch/$(ARCH)/plat-$(PLATFORM)/rcar_version.h 2> /dev/null)
CFG_TEE_IMPL_VERSION ?= R-Car Rev.$(VERSION_OF_RENESAS)
CFG_TEE_MANUFACTURER ?= LINARO & Renesas Electronics
CFG_TEE_FW_IMPL_VERSION ?= $(CFG_TEE_IMPL_VERSION)
CFG_TEE_FW_MANUFACTURER ?= ARM & Renesas Electronics
