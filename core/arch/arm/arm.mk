ifeq ($(CFG_ARM64_core),y)
core-platform-cppflags += -DARM64=1 -DLP64=1
CFG_KERN_LINKER_FORMAT ?= elf64-littleaarch64
CFG_KERN_LINKER_ARCH ?= aarch64
endif
ifeq ($(CFG_ARM32_core),y)
core-platform-cppflags += -DARM32=1 -D__ILP32__=1
CFG_KERN_LINKER_FORMAT ?= elf32-littlearm
CFG_KERN_LINKER_ARCH ?= arm
endif

ifeq ($(CFG_ARM64_core),y)
core-platform-cppflags += $(arm64-platform-cppflags)
core-platform-cflags += $(arm64-platform-cflags)
core-platform-aflags += $(arm64-platform-aflags)
else
core-platform-cppflags += $(arm32-platform-cppflags)
core-platform-cflags += $(arm32-platform-cflags)
core-platform-aflags += $(arm32-platform-aflags)
endif

ifeq ($(CFG_WITH_PAGER),y)
$(call force,CFG_DISABLE_CONCURRENT_EXEC,y,required by CFG_WITH_PAGER)
endif
