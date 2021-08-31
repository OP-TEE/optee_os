include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := ldelf
sm-$(sm) := y

link-out-dir$(sm) := $(out-dir)/$(sm)

cppflags$(sm)	:= $(core-platform-cppflags)
cflags$(sm)	:= $(core-platform-cflags) -fpie -fvisibility=hidden
aflags$(sm)	:= $(core-platform-aflags)

# ldelf is compiled for the same arch or register width as core
ifeq ($(CFG_ARM64_core),y)
CFG_ARM64_$(sm) := y
endif
ifeq ($(CFG_ARM32_core),y)
CFG_ARM32_$(sm) := y
endif
arch-bits-$(sm) := $(arch-bits-core)

cppflags$(sm)	+= -include $(conf-file)
cppflags$(sm)	+= -DTRACE_LEVEL=$(CFG_TEE_CORE_LOG_LEVEL)
cppflags$(sm)	+= -D__LDELF__

# Use same compiler as for core
CROSS_COMPILE_$(sm)	:= $(CROSS_COMPILE_core)
COMPILER_$(sm)		:= $(COMPILER_core)
include mk/$(COMPILER_$(sm)).mk

base-prefix := $(sm)-

libname = utils
libdir = lib/libutils
include mk/lib.mk

libname = utee
libdir = lib/libutee
include mk/lib.mk

libname = unw
libdir = lib/libunw
include mk/lib.mk

base-prefix :=

subdirs = ldelf
include mk/subdir.mk

include mk/compile.mk

include ldelf/link.mk
