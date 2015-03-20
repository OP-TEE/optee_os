PLATFORM_FLAVOR ?= orly2

platform-cpuarch = cortex-a9
platform-cflags	 = -mcpu=$(platform-cpuarch) -mthumb
platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
platform-cflags += -fno-short-enums -mno-apcs-float -fno-common
platform-cflags += -mfloat-abi=soft
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

CFG_ARM32_user_ta := y
user_ta-platform-cflags = -fpie
