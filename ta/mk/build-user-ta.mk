include mk/cleanvars.mk
sm := $(lastword $(subst /, ,$(dir $(ta-mk-file))))
sm-$(sm) := y

# Select TA target (aka TA dev kit, when delivered)
ta-target := $(strip $(if $(CFG_USER_TA_TARGET_$(sm)), \
		$(filter $(CFG_USER_TA_TARGET_$(sm)), $(ta-targets)), \
		$(default-user-ta-target)))

ta-dev-kit-dir$(sm) := $(out-dir)/export-$(ta-target)
link-out-dir$(sm) := $(out-dir)/$(patsubst %/,%, $(dir $(ta-mk-file)))

include $(ta-mk-file)
ifeq ($(user-ta-uuid),)
$(error user-ta-uuid missing in $(ta-mk-file))
endif

# Inherit compiler and flags from TA target
CROSS_COMPILE_$(sm)	:= $(CROSS_COMPILE_$(ta-target))
COMPILER_$(sm)		:= $(COMPILER_$(ta-target))
include mk/$(COMPILER_$(sm)).mk

cppflags$(sm)	:= $(cppflags$(ta-target)) -I$(ta-dev-kit-dir$(sm))/include
cflags$(sm)	:= $(cflags$(ta-target))
aflags$(sm)	:= $(aflags$(ta-target))

ifeq ($(CFG_ULIBS_SHARED),y)
# For now, do not link in-tree TAs against shared libraries
link-ldflags$(sm) := -static
endif

libdirs  = $(ta-dev-kit-dir$(sm))/lib
libnames = utils utee
ifeq ($(CFG_TA_MBEDTLS),y)
libnames += mbedtls
endif
libdeps = $(addsuffix .a, $(addprefix $(libdirs)/lib, $(libnames)))

subdirs = $(patsubst %/,%,$(dir $(ta-mk-file)))
include mk/subdir.mk

spec-out-dir := $(link-out-dir$(sm))
spec-srcs += $(ta-dev-kit-dir$(sm))/src/user_ta_header.c
ifeq ($(ta-target),ta_arm32)
spec-srcs += $(ta-dev-kit-dir$(sm))/src/ta_entry_a32.S
endif

# Install TA headers before in-tree TAs can be compiled
additional-compile-deps := $(ta_dev_kit-files-include)
include mk/compile.mk
# Install TA libraries before in-tree TAs can be linked
additional-link-deps := $(ta_dev_kit-files-lib)
include  ta/arch/$(ARCH)/link.mk
