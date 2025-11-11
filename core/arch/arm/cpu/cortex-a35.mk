arm32-platform-cpuarch := cortex-a35
include core/arch/arm/cpu/cortex-armv8-0.mk

# ARM debugger needs this
platform-cflags-debug-info = -gdwarf-2
platform-aflags-debug-info = -gdwarf-2

arm64-platform-cflags += -mcpu=cortex-a35
arm64-platform-aflags += -mcpu=cortex-a35
