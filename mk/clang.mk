# CROSS_COMPILE/CROSS_COMPILE32/CROSS_COMPILE64 indicate the target that should
# be passed to clang. Path components are ignored, as well as any command
# before the compiler name (e.g., "ccache arm-linux-gnueabihf-").
clang-target	:= $(patsubst %-,%,$(notdir $(lastword $(CROSS_COMPILE_$(sm)))))

CC$(sm)		:= clang --target=$(clang-target)
CPP$(sm)	:= clang-cpp --target=$(clang-target)
ifeq ($(sm),core)
# Avoiding issues with generation of all_objs.o and unpaged.o when
# CFG_WITH_PAGER=y (ld.lld bug?):
# ld.ldd merges .text.* sections into .text, even though the linker script
# does not tell to do so. --relocatable avoids that, but unfortunately this is
# not compatible with --gc-sections
LDcore		:= $(CROSS_COMPILE_$(sm))ld
else
LD$(sm)		:= ld.lld
endif
AR$(sm)		:= llvm-ar
NM$(sm)		:= llvm-nm
OBJCOPY$(sm)	:= ./scripts/llvm-objcopy-wrapper
# llvm-objdump:
# - Does not support mixed i32-bit ARM and Thumb instructions
# - Has a poorer output than the binutils version (static functions not shown,
#   for instance).
# Rely on the GNU binutils version instead (if available).
binutils-objdump = $(CROSS_COMPILE_$(sm))objdump
ifneq (,$(filter GNU,$(shell $(binutils-objdump) -v 2>&1)))
OBJDUMP$(sm)	:= $(binutils-objdump)
else
OBJDUMP$(sm)	:= echo "Warning: binutils objdump not found, file will be empty" >&2; true
endif
READELF$(sm)	:= llvm-readelf

nostdinc$(sm)	:= -nostdinc -isystem $(shell $(CC$(sm)) \
			-print-file-name=include 2> /dev/null)

cflags_compiler_clang := -Wno-language-extension-token \
			 -Wno-gnu-zero-variadic-macro-arguments

Wno-suggest-attribute--noreturn :=
MDflag := -dependency-file

# Get location of libgcc from gcc
libgcc$(sm)  	:=

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


