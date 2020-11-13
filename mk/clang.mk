# CROSS_COMPILE_$(sm) is derived from CROSS_COMPILE/CROSS_COMPILE32/
# CROSS_COMPILE64 and indicates the target that should be passed to clang. Path
# components are ignored, as well as any command before the compiler name (for
# instance "/some/path/ccache /other/path/arm-linux-gnueabihf-").
# We try to extract any ccache command if present.
clang-target	:= $(patsubst %-,%,$(notdir $(lastword $(CROSS_COMPILE_$(sm)))))
ccache-cmd	:= $(if $(findstring ccache,$(CROSS_COMPILE_$(sm))),$(firstword $(CROSS_COMPILE_$(sm))) ,)

CC$(sm)		:= $(ccache-cmd)clang --target=$(clang-target)
CXX$(sm)	:= false # Untested yet
# Due to the absence of clang-cpp in AOSP's prebuilt version of clang,
# use the equivalent command of 'clang -E'
CPP$(sm)	:= $(ccache-cmd)clang --target=$(clang-target) -E
LD$(sm)		:= $(ccache-cmd)ld.lld

AR$(sm)		:= $(ccache-cmd)llvm-ar
NM$(sm)		:= llvm-nm
OBJCOPY$(sm)	:= llvm-objcopy
OBJDUMP$(sm)	:= llvm-objdump
READELF$(sm)	:= llvm-readelf

nostdinc$(sm)	:= -nostdinc -isystem $(shell $(CC$(sm)) \
			-print-file-name=include 2> /dev/null)

comp-cflags-warns-clang := -Wno-language-extension-token \
			 -Wno-gnu-zero-variadic-macro-arguments

# Note, use the compiler runtime library (libclang_rt.builtins.*.a) instead of
# libgcc for clang
libgcc$(sm)	:= $(shell $(CC$(sm)) $(CFLAGS$(arch-bits-$(sm))) \
			-rtlib=compiler-rt -print-libgcc-file-name 2> /dev/null)

# Core ASLR relies on the executable being ready to run from its preferred load
# address, because some symbols are used before the MMU is enabled and the
# relocations are applied.
ldflag-apply-dynamic-relocs := --apply-dynamic-relocs

# Define these to something to discover accidental use
CC		:= false
CXX		:= false
CPP		:= false
LD		:= false
AR		:= false
NM		:= false
OBJCOPY		:= false
OBJDUMP		:= false
READELF		:= false
nostdinc	:= --bad-nostdinc-variable
libgcc  	:= --bad-libgcc-variable

