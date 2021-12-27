# Setup compiler for the core module
ifeq ($(CFG_RV64_core),y)
arch-bits-core := 64
else
arch-bits-core := 32
endif
CROSS_COMPILE_core := $(CROSS_COMPILE$(arch-bits-core))
COMPILER_core := $(COMPILER)

include mk/$(COMPILER_core).mk

# Defines the cc-option macro using the compiler set for the core module
include mk/cc-option.mk

CFG_MMAP_REGIONS ?= 13
CFG_RESERVED_VASPACE_SIZE ?= (1024 * 1024 * 10)

ifeq ($(CFG_RV64_core),y)
CFG_KERN_LINKER_FORMAT ?= elf64-littleriscv
CFG_KERN_LINKER_ARCH ?= riscv
else
ifeq ($(CFG_RV32_core),y)
CFG_KERN_LINKER_FORMAT ?= elf32-littleriscv
CFG_KERN_LINKER_ARCH ?= riscv
else
$(error Error: CFG_RV64_core or CFG_RV32_core should be defined)
endif
endif

CFG_CORE_RWDATA_NOEXEC ?= y
CFG_CORE_RODATA_NOEXEC ?= n
ifeq ($(CFG_CORE_RODATA_NOEXEC),y)
$(call force,CFG_CORE_RWDATA_NOEXEC,y)
endif

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel) $(platform-dir)

# more convenient to move it to platform instead
rv64-platform-cppflags += -mcmodel=medany -march=rv64imafd -mabi=lp64d
rv64-platform-cppflags += -Wno-missing-include-dirs

rv64-platform-cppflags += -DRV64=1 -D__LP64__=1
rv32-platform-cppflags += -DRV32=1 -D__ILP32__=1

platform-cflags-generic ?= -ffunction-sections -fdata-sections -pipe
platform-aflags-generic ?= -pipe

rv64-platform-cflags-generic := -mstrict-align $(call cc-option,)

# Optimize for size by default, usually gives good performance too
CFG_CC_OPT_LEVEL ?= 0
platform-cflags-optimization ?= -O$(CFG_CC_OPT_LEVEL)

CFG_DEBUG_INFO ?= y
ifeq ($(CFG_DEBUG_INFO),y)
platform-cflags-debug-info ?= -g3
platform-aflags-debug-info ?= -g
endif

core-platform-cflags += $(platform-cflags-optimization)
core-platform-cflags += $(platform-cflags-generic)
core-platform-cflags += $(platform-cflags-debug-info)

core-platform-aflags += $(platform-aflags-generic)
core-platform-aflags += $(platform-aflags-debug-info)

ifeq ($(CFG_CORE_ASLR),y)
core-platform-cflags += -fpie
endif

ifeq ($(CFG_RV64_core),y)
core-platform-cppflags += $(rv64-platform-cppflags)
core-platform-cflags += $(rv64-platform-cflags)
core-platform-cflags += $(rv64-platform-cflags-generic)
core-platform-cflags += $(rv64-platform-cflags-no-hard-float)
core-platform-aflags += $(rv64-platform-aflags)
else
core-platform-cppflags += $(rv32-platform-cppflags)
core-platform-cflags += $(rv32-platform-cflags)
core-platform-cflags += $(rv32-platform-cflags-no-hard-float)
ifeq ($(CFG_UNWIND),y)
core-platform-cflags += -funwind-tables
endif
core-platform-aflags += $(core_rv32-platform-aflags)
core-platform-aflags += $(rv32-platform-aflags)
endif

# Provide default supported-ta-targets if not set by the platform config
ifeq (,$(supported-ta-targets))
supported-ta-targets = ta_rv32
ifeq ($(CFG_RV64_core),y)
supported-ta-targets += ta_rv64
endif
endif

ta-targets := $(if $(CFG_USER_TA_TARGETS),$(filter $(supported-ta-targets),$(CFG_USER_TA_TARGETS)),$(supported-ta-targets))
unsup-targets := $(filter-out $(ta-targets),$(CFG_USER_TA_TARGETS))
ifneq (,$(unsup-targets))
$(error CFG_USER_TA_TARGETS contains unsupported value(s): $(unsup-targets). Valid values: $(supported-ta-targets))
endif

ifneq ($(filter ta_rv32,$(ta-targets)),)
# Variables for ta-target/sm "ta_rv32"
CFG_RV32_ta_rv32 := y
arch-bits-ta_rv32 := 32
ta_rv32-platform-cppflags += $(rv32-platform-cppflags)
ta_rv32-platform-cflags += $(rv32-platform-cflags)
ta_rv32-platform-cflags += $(platform-cflags-optimization)
ta_rv32-platform-cflags += $(platform-cflags-debug-info)
ta_rv32-platform-cflags += -fpic

ifeq ($(CFG_UNWIND),y)
ta_rv32-platform-cflags += -funwind-tables
endif
ta_rv32-platform-aflags += $(platform-aflags-generic)
ta_rv32-platform-aflags += $(platform-aflags-debug-info)
ta_rv32-platform-aflags += $(rv32-platform-aflags)

ta_rv32-platform-cxxflags += -fpic
ta_rv32-platform-cxxflags += $(rv32-platform-cxxflags)
ta_rv32-platform-cxxflags += $(platform-cflags-optimization)
ta_rv32-platform-cxxflags += $(platform-cflags-debug-info)

ta-mk-file-export-vars-ta_rv32 += CFG_RV32_ta_rv32
ta-mk-file-export-vars-ta_rv32 += ta_rv32-platform-cppflags
ta-mk-file-export-vars-ta_rv32 += ta_rv32-platform-cflags
ta-mk-file-export-vars-ta_rv32 += ta_rv32-platform-aflags
ta-mk-file-export-vars-ta_rv32 += ta_rv32-platform-cxxflags

ta-mk-file-export-add-ta_rv32 += CROSS_COMPILE ?= riscv32-unknown-linux-gnu-_nl_
ta-mk-file-export-add-ta_rv32 += CROSS_COMPILE32 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_rv32 += CROSS_COMPILE_ta_rv32 ?= $$(CROSS_COMPILE32)_nl_
ta-mk-file-export-add-ta_rv32 += COMPILER ?= gcc_nl_
ta-mk-file-export-add-ta_rv32 += COMPILER_ta_rv32 ?= $$(COMPILER)_nl_
ta-mk-file-export-add-ta_rv32 += PYTHON3 ?= python3_nl_
endif

ifneq ($(filter ta_rv64,$(ta-targets)),)
# Variables for ta-target/sm "ta_rv64"
CFG_RV64_ta_rv64 := y
arch-bits-ta_rv64 := 64
ta_rv64-platform-cppflags += $(rv64-platform-cppflags)
ta_rv64-platform-cflags += $(rv64-platform-cflags)
ta_rv64-platform-cflags += $(platform-cflags-optimization)
ta_rv64-platform-cflags += $(platform-cflags-debug-info)
ta_rv64-platform-cflags += -fpic
ta_rv64-platform-cflags += $(rv64-platform-cflags-generic)
ifeq ($(rv64-platform-hard-float-enabled),y)
ta_rv64-platform-cflags += $(rv64-platform-cflags-hard-float)
else
ta_rv64-platform-cflags += $(rv64-platform-cflags-no-hard-float)
endif
ta_rv64-platform-aflags += $(platform-aflags-generic)
ta_rv64-platform-aflags += $(platform-aflags-debug-info)
ta_rv64-platform-aflags += $(rv64-platform-aflags)

ta_rv64-platform-cxxflags += -fpic
ta_rv64-platform-cxxflags += $(platform-cflags-optimization)
ta_rv64-platform-cxxflags += $(platform-cflags-debug-info)

ta-mk-file-export-vars-ta_rv64 += CFG_RV64_ta_rv64
ta-mk-file-export-vars-ta_rv64 += ta_rv64-platform-cppflags
ta-mk-file-export-vars-ta_rv64 += ta_rv64-platform-cflags
ta-mk-file-export-vars-ta_rv64 += ta_rv64-platform-aflags
ta-mk-file-export-vars-ta_rv64 += ta_rv64-platform-cxxflags

ta-mk-file-export-add-ta_rv64 += CROSS_COMPILE64 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_rv64 += CROSS_COMPILE_ta_rv64 ?= $$(CROSS_COMPILE64)_nl_
ta-mk-file-export-add-ta_rv64 += COMPILER ?= gcc_nl_
ta-mk-file-export-add-ta_rv64 += COMPILER_ta_rv64 ?= $$(COMPILER)_nl_
ta-mk-file-export-add-ta_rv64 += PYTHON3 ?= python3_nl_
endif

# Set cross compiler prefix for each TA target
$(foreach sm, $(ta-targets), $(eval CROSS_COMPILE_$(sm) ?= $(CROSS_COMPILE$(arch-bits-$(sm)))))
