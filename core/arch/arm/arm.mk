CFG_LTC_OPTEE_THREAD ?= y
# Size of emulated TrustZone protected SRAM, 448 kB.
# Only applicable when paging is enabled.
CFG_CORE_TZSRAM_EMUL_SIZE ?= 458752
CFG_LPAE_ADDR_SPACE_SIZE ?= (1ull << 32)

CFG_MMAP_REGIONS ?= 13
CFG_RESERVED_VASPACE_SIZE ?= (1024 * 1024 * 10)

ifeq ($(CFG_ARM64_core),y)
CFG_KERN_LINKER_FORMAT ?= elf64-littleaarch64
CFG_KERN_LINKER_ARCH ?= aarch64
else
ifeq ($(CFG_ARM32_core),y)
CFG_KERN_LINKER_FORMAT ?= elf32-littlearm
CFG_KERN_LINKER_ARCH ?= arm
else
$(error Error: CFG_ARM64_core or CFG_ARM32_core should be defined)
endif
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
arm64-platform-hard-float-enabled := y
ifneq ($(CFG_TA_ARM32_NO_HARD_FLOAT_SUPPORT),y)
arm32-platform-hard-float-enabled := y
endif
endif
endif

# Adds protection against CVE-2017-5715 also know as Spectre
# (https://spectreattack.com)
# See also https://developer.arm.com/-/media/Files/pdf/Cache_Speculation_Side-channels.pdf
# Variant 2
CFG_CORE_WORKAROUND_SPECTRE_BP ?= y
# Same as CFG_CORE_WORKAROUND_SPECTRE_BP but targeting exceptions from
# secure EL0 instead of non-secure world.
CFG_CORE_WORKAROUND_SPECTRE_BP_SEC ?= $(CFG_CORE_WORKAROUND_SPECTRE_BP)

CFG_CORE_RWDATA_NOEXEC ?= y
CFG_CORE_RODATA_NOEXEC ?= n
ifeq ($(CFG_CORE_RODATA_NOEXEC),y)
$(call force,CFG_CORE_RWDATA_NOEXEC,y)
endif
# 'y' to set the Alignment Check Enable bit in SCTLR/SCTLR_EL1, 'n' to clear it
CFG_SCTLR_ALIGNMENT_CHECK ?= y

ifeq ($(CFG_CORE_LARGE_PHYS_ADDR),y)
$(call force,CFG_WITH_LPAE,y)
endif

# Unmaps all kernel mode code except the code needed to take exceptions
# from user space and restore kernel mode mapping again. This gives more
# strict control over what is accessible while in user mode.
# Addresses CVE-2017-5715 (aka Meltdown) known to affect Arm Cortex-A75
CFG_CORE_UNMAP_CORE_AT_EL0 ?= y

# Initialize PMCR.DP to 1 to prohibit cycle counting in secure state, and
# save/restore PMCR during world switch.
CFG_SM_NO_CYCLE_COUNTING ?= y

ifeq ($(CFG_ARM32_core),y)
# Configration directive related to ARMv7 optee boot arguments.
# CFG_PAGEABLE_ADDR: if defined, forces pageable data physical address.
# CFG_NS_ENTRY_ADDR: if defined, forces NS World physical entry address.
# CFG_DT_ADDR:       if defined, forces Device Tree data physical address.
endif

core-platform-cppflags	+= -I$(arch-dir)/include
core-platform-subdirs += \
	$(addprefix $(arch-dir)/, kernel crypto mm tee pta) $(platform-dir)

ifneq ($(CFG_WITH_ARM_TRUSTED_FW),y)
core-platform-subdirs += $(arch-dir)/sm
endif

arm64-platform-cppflags += -DARM64=1 -D__LP64__=1
arm32-platform-cppflags += -DARM32=1 -D__ILP32__=1

platform-cflags-generic ?= -ffunction-sections -fdata-sections -pipe
platform-aflags-generic ?= -pipe

arm32-platform-cflags-no-hard-float ?= -mfloat-abi=soft
arm32-platform-cflags-hard-float ?= -mfloat-abi=hard -funsafe-math-optimizations
arm32-platform-cflags-generic ?= -mthumb -mthumb-interwork \
			-fno-short-enums -fno-common -mno-unaligned-access
arm32-platform-aflags-no-hard-float ?=

arm64-platform-cflags-no-hard-float ?= -mgeneral-regs-only
arm64-platform-cflags-hard-float ?=
arm64-platform-cflags-generic ?= -mstrict-align

ifeq ($(DEBUG),1)
# For backwards compatibility
$(call force,CFG_CC_OPTIMIZE_FOR_SIZE,n)
$(call force,CFG_DEBUG_INFO,y)
endif

CFG_CC_OPTIMIZE_FOR_SIZE ?= y
ifeq ($(CFG_CC_OPTIMIZE_FOR_SIZE),y)
platform-cflags-optimization ?= -Os
else
platform-cflags-optimization ?= -O0
endif

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

ifeq ($(CFG_ARM64_core),y)
arch-bits-core := 64
core-platform-cppflags += $(arm64-platform-cppflags)
core-platform-cflags += $(arm64-platform-cflags)
core-platform-cflags += $(arm64-platform-cflags-generic)
core-platform-cflags += $(arm64-platform-cflags-no-hard-float)
core-platform-aflags += $(arm64-platform-aflags)
else
arch-bits-core := 32
core-platform-cppflags += $(arm32-platform-cppflags)
core-platform-cflags += $(arm32-platform-cflags)
core-platform-cflags += $(arm32-platform-cflags-no-hard-float)
ifeq ($(CFG_UNWIND),y)
core-platform-cflags += -funwind-tables
endif
core-platform-cflags += $(arm32-platform-cflags-generic)
core-platform-aflags += $(core_arm32-platform-aflags)
core-platform-aflags += $(arm32-platform-aflags)
endif

# Provide default supported-ta-targets if not set by the platform config
ifeq (,$(supported-ta-targets))
supported-ta-targets = ta_arm32
ifeq ($(CFG_ARM64_core),y)
supported-ta-targets += ta_arm64
endif
endif

ta-targets := $(if $(CFG_USER_TA_TARGETS),$(filter $(supported-ta-targets),$(CFG_USER_TA_TARGETS)),$(supported-ta-targets))
unsup-targets := $(filter-out $(ta-targets),$(CFG_USER_TA_TARGETS))
ifneq (,$(unsup-targets))
$(error CFG_USER_TA_TARGETS contains unsupported value(s): $(unsup-targets). Valid values: $(supported-ta-targets))
endif

ifneq ($(filter ta_arm32,$(ta-targets)),)
# Variables for ta-target/sm "ta_arm32"
CFG_ARM32_ta_arm32 := y
arch-bits-ta_arm32 := 32
ta_arm32-platform-cppflags += $(arm32-platform-cppflags)
ta_arm32-platform-cflags += $(arm32-platform-cflags)
ta_arm32-platform-cflags += $(platform-cflags-optimization)
ta_arm32-platform-cflags += $(platform-cflags-debug-info)
ta_arm32-platform-cflags += -fpie
ta_arm32-platform-cflags += $(arm32-platform-cflags-generic)
ifeq ($(arm32-platform-hard-float-enabled),y)
ta_arm32-platform-cflags += $(arm32-platform-cflags-hard-float)
else
ta_arm32-platform-cflags += $(arm32-platform-cflags-no-hard-float)
endif
ifeq ($(CFG_UNWIND),y)
ta_arm32-platform-cflags += -funwind-tables
endif
ta_arm32-platform-aflags += $(platform-aflags-generic)
ta_arm32-platform-aflags += $(platform-aflags-debug-info)
ta_arm32-platform-aflags += $(arm32-platform-aflags)

ta-mk-file-export-vars-ta_arm32 += CFG_ARM32_ta_arm32
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-cppflags
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-cflags
ta-mk-file-export-vars-ta_arm32 += ta_arm32-platform-aflags

ta-mk-file-export-add-ta_arm32 += CROSS_COMPILE ?= arm-linux-gnueabihf-_nl_
ta-mk-file-export-add-ta_arm32 += CROSS_COMPILE32 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_arm32 += CROSS_COMPILE_ta_arm32 ?= $$(CROSS_COMPILE32)_nl_
endif

ifneq ($(filter ta_arm64,$(ta-targets)),)
# Variables for ta-target/sm "ta_arm64"
CFG_ARM64_ta_arm64 := y
arch-bits-ta_arm64 := 64
ta_arm64-platform-cppflags += $(arm64-platform-cppflags)
ta_arm64-platform-cflags += $(arm64-platform-cflags)
ta_arm64-platform-cflags += $(platform-cflags-optimization)
ta_arm64-platform-cflags += $(platform-cflags-debug-info)
ta_arm64-platform-cflags += -fpie
ta_arm64-platform-cflags += $(arm64-platform-cflags-generic)
ifeq ($(arm64-platform-hard-float-enabled),y)
ta_arm64-platform-cflags += $(arm64-platform-cflags-hard-float)
else
ta_arm64-platform-cflags += $(arm64-platform-cflags-no-hard-float)
endif
ta_arm64-platform-aflags += $(platform-aflags-generic)
ta_arm64-platform-aflags += $(platform-aflags-debug-info)
ta_arm64-platform-aflags += $(arm64-platform-aflags)

ta-mk-file-export-vars-ta_arm64 += CFG_ARM64_ta_arm64
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-cppflags
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-cflags
ta-mk-file-export-vars-ta_arm64 += ta_arm64-platform-aflags

ta-mk-file-export-add-ta_arm64 += CROSS_COMPILE64 ?= $$(CROSS_COMPILE)_nl_
ta-mk-file-export-add-ta_arm64 += CROSS_COMPILE_ta_arm64 ?= $$(CROSS_COMPILE64)_nl_
endif

# Set cross compiler prefix for each submodule
$(foreach sm, core $(ta-targets), $(eval CROSS_COMPILE_$(sm) ?= $(CROSS_COMPILE$(arch-bits-$(sm)))))

arm32-sysreg-txt = core/arch/arm/kernel/arm32_sysreg.txt
arm32-sysregs-$(arm32-sysreg-txt)-h := arm32_sysreg.h
arm32-sysregs-$(arm32-sysreg-txt)-s := arm32_sysreg.S
arm32-sysregs += $(arm32-sysreg-txt)

ifeq ($(CFG_ARM_GICV3),y)
arm32-gicv3-sysreg-txt = core/arch/arm/kernel/arm32_gicv3_sysreg.txt
arm32-sysregs-$(arm32-gicv3-sysreg-txt)-h := arm32_gicv3_sysreg.h
arm32-sysregs-$(arm32-gicv3-sysreg-txt)-s := arm32_gicv3_sysreg.S
arm32-sysregs += $(arm32-gicv3-sysreg-txt)
endif

arm32-sysregs-out := $(out-dir)/$(sm)/include/generated

define process-arm32-sysreg
FORCE-GENSRC$(sm): $$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-h)
cleanfiles := $$(cleanfiles) $$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-h)

$$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-h): $(1) scripts/arm32_sysreg.py
	@$(cmd-echo-silent) '  GEN     $$@'
	$(q)mkdir -p $$(dir $$@)
	$(q)scripts/arm32_sysreg.py --guard __$$(arm32-sysregs-$(1)-h) \
		< $$< > $$@

FORCE-GENSRC$(sm): $$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-s)
cleanfiles := $$(cleanfiles) $$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-s)

$$(arm32-sysregs-out)/$$(arm32-sysregs-$(1)-s): $(1) scripts/arm32_sysreg.py
	@$(cmd-echo-silent) '  GEN     $$@'
	$(q)mkdir -p $$(dir $$@)
	$(q)scripts/arm32_sysreg.py --s_file < $$< > $$@
endef #process-arm32-sysreg

$(foreach sr, $(arm32-sysregs), $(eval $(call process-arm32-sysreg,$(sr))))
