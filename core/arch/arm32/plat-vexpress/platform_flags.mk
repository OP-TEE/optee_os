PLATFORM_FLAVOR ?= fvp
PLATFORM_FLAVOR_$(PLATFORM_FLAVOR) := y

platform-cpuarch = cortex-a15
platform-cflags	 = -mcpu=$(platform-cpuarch) -mthumb
platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
platform-cflags += -fno-short-enums -mno-apcs-float -fno-common
platform-cflags += -mfloat-abi=soft
platform-cflags += -mno-unaligned-access
platform-aflags	 = -mcpu=$(platform-cpuarch)

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

user_ta-platform-cflags = -fpie
