# 32-bit flags
arm32-platform-cpuarch	:= cortex-a15
arm32-platform-cflags	+= -mcpu=$(arm32-platform-cpuarch) -mthumb
arm32-platform-cflags	+= -pipe -mthumb-interwork -mlong-calls
arm32-platform-cflags	+= -fno-short-enums -mno-apcs-float -fno-common
arm32-platform-cflags	+= -mfloat-abi=soft
arm32-platform-cflags	+= -mno-unaligned-access
arm32-platform-aflags	+= -mcpu=$(arm32-platform-cpuarch)
arm32-platform-aflags	+= -mfpu=neon

# 64-bit flags
arm64-platform-cflags	+= -mgeneral-regs-only
arm64-platform-cflags	+= -mstrict-align

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
user_ta-platform-cflags += $(arm32-platform-cflags)
user_ta-platform-cflags += -fpie
user_ta-platform-cppflags += $(arm32-platform-cppflags)
user_ta-platform-aflags += $(arm32-platform-aflags)
