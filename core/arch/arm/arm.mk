CFG_LTC_OPTEE_THREAD ?= y

ifeq ($(CFG_ARM64_core),y)
CFG_KERN_LINKER_FORMAT ?= elf64-littleaarch64
CFG_KERN_LINKER_ARCH ?= aarch64
endif
ifeq ($(CFG_ARM32_core),y)
CFG_KERN_LINKER_FORMAT ?= elf32-littlearm
CFG_KERN_LINKER_ARCH ?= arm
endif

ifeq ($(CFG_TA_FLOAT_SUPPORT),y)
# Use hard-float for floating point support in user TAs instead of
# soft-float
CFG_WITH_VFP ?= y
ifeq ($(CFG_ARM64_core),y)
# AArch64 has no fallback to soft-float
$(call force,CFG_WITH_VFP,y)
endif
ifeq ($(CFG_WITH_VFP),y)
platform-hard-float-enabled := y
endif
endif


core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel mm tee sta) $(platform-dir)

ifneq ($(CFG_WITH_ARM_TRUSTED_FW),y)
core-platform-subdirs += $(arch-dir)/sm
endif

arm64-platform-cppflags += -DARM64=1 -D__LP64__=1
arm32-platform-cppflags += -DARM32=1 -D__ILP32__=1

platform-cflags-generic ?= -g -ffunction-sections -fdata-sections -pipe
platform-aflags-generic ?= -g -pipe

arm32-platform-cflags-no-hard-float ?= -mno-apcs-float -mfloat-abi=soft
arm32-platform-cflags-hard-float ?= -mfloat-abi=hard -funsafe-math-optimizations
arm32-platform-cflags-generic ?= -mthumb -mthumb-interwork -mlong-calls \
			-fno-short-enums -fno-common -mno-unaligned-access
arm32-platform-aflags-no-hard-float ?=

arm64-platform-cflags-no-hard-float ?= -mgeneral-regs-only
arm64-platform-cflags-hard-float ?=
arm64-platform-cflags-generic ?= -mstrict-align

ifeq ($(DEBUG),1)
platform-cflags-optimization ?=  -O0
else
platform-cflags-optimization ?=  -Os
endif

platform-cflags-debug-info ?= -g3
platform-aflags-debug-info ?=

core-platform-cflags += $(platform-cflags-optimization)
core-platform-cflags += $(platform-cflags-generic)
core-platform-cflags += $(platform-cflags-debug-info)

core-platform-aflags += $(platform-aflags-generic)
core-platform-aflags += $(platform-aflags-debug-info)

ifeq ($(CFG_ARM64_core),y)
CROSS_COMPILE_core ?= $(CROSS_COMPILE64)
core-platform-cppflags += $(arm64-platform-cppflags)
core-platform-cflags += $(arm64-platform-cflags)
core-platform-cflags += $(arm64-platform-cflags-generic)
core-platform-cflags += $(arm64-platform-cflags-no-hard-float)
core-platform-aflags += $(arm64-platform-aflags)
else
CROSS_COMPILE_core ?= $(CROSS_COMPILE32)
core-platform-cppflags += $(arm32-platform-cppflags)
core-platform-cflags += $(arm32-platform-cflags)
core-platform-cflags += $(arm32-platform-cflags-no-hard-float)
ifeq ($(CFG_CORE_UNWIND),y)
core-platform-cflags += -funwind-tables
endif
core-platform-cflags += $(arm32-platform-cflags-generic)
core-platform-aflags += $(core_arm32-platform-aflags)
core-platform-aflags += $(arm32-platform-aflags)
endif

ifneq ($(filter ta_arm32,$(ta-targets)),)
# Variables for ta-target/sm "ta_arm32"
CFG_ARM32_ta_arm32 := y
CROSS_COMPILE_ta_arm32 ?= $(CROSS_COMPILE32)
ta_arm32-platform-cppflags += $(arm32-platform-cppflags)
ta_arm32-platform-cflags += $(arm32-platform-cflags)
ta_arm32-platform-cflags += $(platform-cflags-optimization)
ta_arm32-platform-cflags += $(platform-cflags-debug-info)
ta_arm32-platform-cflags += -fpie
ta_arm32-platform-cflags += $(arm32-platform-cflags-generic)
ifeq ($(platform-hard-float-enabled),y)
ta_arm32-platform-cflags += $(arm32-platform-cflags-hard-float)
else
ta_arm32-platform-cflags += $(arm32-platform-cflags-no-hard-float)
endif
ta_arm32-platform-aflags += $(platform-aflags-debug-info)
ta_arm32-platform-aflags += $(arm32-platform-aflags)

ta-mk-file-export-vars-ta_arm32 += CFG_ARM32_ta_arm32
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-cppflags
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-cflags
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-aflags

ta-mk-file-export-add-ta_arm32 += CROSS_COMPILE32 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_arm32 += CROSS_COMPILE_ta_arm32 ?= $$(CROSS_COMPILE32)_nl_
endif

ifneq ($(filter ta_arm64,$(ta-targets)),)
# Variables for ta-target/sm "ta_arm64"
CFG_ARM64_ta_arm64 := y
CROSS_COMPILE_ta_arm64 ?= $(CROSS_COMPILE64)
ta_arm64-platform-cppflags += $(arm64-platform-cppflags)
ta_arm64-platform-cflags += $(arm64-platform-cflags)
ta_arm64-platform-cflags += $(platform-cflags-optimization)
ta_arm64-platform-cflags += $(platform-cflags-debug-info)
ta_arm64-platform-cflags += -fpie
ta_arm64-platform-cflags += $(arm64-platform-cflags-generic)
ifeq ($(platform-hard-float-enabled),y)
ta_arm64-platform-cflags += $(arm64-platform-cflags-hard-float)
else
ta_arm64-platform-cflags += $(arm64-platform-cflags-no-hard-float)
endif
ta_arm64-platform-aflags += $(platform-aflags-debug-info)
ta_arm64-platform-aflags += $(arm64-platform-aflags)

ta-mk-file-export-vars-ta_arm64 += CFG_ARM64_ta_arm64
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-cppflags
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-cflags
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-aflags

ta-mk-file-export-add-ta_arm64 += CROSS_COMPILE64 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_arm64 += CROSS_COMPILE_ta_arm64 ?= $$(CROSS_COMPILE64)_nl_
endif
