# CROSS_COMPILE_$(sm) is derived from CROSS_COMPILE/CROSS_COMPILE32/
# CROSS_COMPILE64 and indicates the target that should be passed to clang. Path
# components are ignored, as well as any command before the compiler name (for
# instance "/some/path/ccache /other/path/arm-linux-gnueabihf-").
# We try to extract any ccache command if present.
clang-target	:= $(patsubst %-,%,$(notdir $(lastword $(CROSS_COMPILE_$(sm)))))
ccache-cmd	:= $(if $(findstring ccache,$(CROSS_COMPILE_$(sm))),$(firstword $(CROSS_COMPILE_$(sm))) ,)

CC$(sm)		:= $(ccache-cmd)clang --target=$(clang-target)
# Due to the absence of clang-cpp in AOSP's prebuilt version of clang,
# use the equivalent command of 'clang -E'
CPP$(sm)	:= $(ccache-cmd)clang --target=$(clang-target) -E
LD$(sm)		:= $(ccache-cmd)ld.lld

ifeq ($(sm)-$(CFG_WITH_PAGER),core-y)
# Workaround an issue with all_objs.o and unpaged.o when CFG_WITH_PAGER=y:
# ld.ldd merges .text.* sections into .text, even though the linker script does
# not tell to do so. --relocatable would avoid that, but is not compatible with
# --gc-sections. A trivial patch to ld.lld can fix the issue (in
# lld/ELF/Writer.cpp, change elf::getOutputSectionName() to always return
# s->name) so perhaps a new command line option could be proposed upstream?
# Anyway, use GNU.ld for the moment.
LDcore		:= $(CROSS_COMPILE_$(sm))ld
endif

AR$(sm)		:= $(ccache-cmd)llvm-ar
NM$(sm)		:= llvm-nm
OBJCOPY$(sm)	:= llvm-objcopy
OBJDUMP$(sm)	:= llvm-objdump
READELF$(sm)	:= llvm-readelf

nostdinc$(sm)	:= -nostdinc -isystem $(shell $(CC$(sm)) \
			-print-file-name=include 2> /dev/null)

comp-cflags-warns-clang := -Wno-language-extension-token \
			 -Wno-gnu-zero-variadic-macro-arguments

# Note, the currently used compiler runtime library may be libgcc.a or
# libclang_rt.builtins.*.a depending on the compiler build-time configuration.
libgcc$(sm)  	:= $(shell $(CC$(sm)) $(CFLAGS$(arch-bits-$(sm))) $(comp-cflags$(sm)) \
			-print-libgcc-file-name 2> /dev/null)

# Core ASLR relies on the executable being ready to run from its preferred load
# address, because some symbols are used before the MMU is enabled and the
# relocations are applied.
ldflag-apply-dynamic-relocs := --apply-dynamic-relocs

# Define these to something to discover accidental use
CC		:= false
CPP		:= false
LD		:= false
AR		:= false
NM		:= false
OBJCOPY		:= false
OBJDUMP		:= false
READELF		:= false
nostdinc	:= --bad-nostdinc-variable
libgcc  	:= --bad-libgcc-variable

