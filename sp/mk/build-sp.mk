include mk/cleanvars.mk
sm := $(lastword $(subst /, ,$(dir $(sp-mk-file))))
sm-$(sm) := y

# Select SP target (aka SP dev kit, when delivered)
sp-target := $(strip $(if $(CFG_SP_TARGET_$(sm)), \
		$(filter $(CFG_SP_TARGET_$(sm)), $(sp-targets)), \
		$(default-sp-target)))

sp-dev-kit-dir$(sm) := $(out-dir)/export-$(sp-target)
link-out-dir$(sm) := $(out-dir)/$(patsubst %/,%, $(dir $(sp-mk-file)))

# Default if sp-mk-file defines none
sp-version := 0

include $(sp-mk-file)
ifeq ($(sp-uuid),)
$(error sp-uuid missing in $(sp-mk-file))
endif

# Inherit compiler and flags from SP target
CROSS_COMPILE_$(sm)	:= $(CROSS_COMPILE_$(sp-target))
COMPILER_$(sm)		:= $(COMPILER_$(sp-target))
include mk/$(COMPILER_$(sm)).mk

cppflags$(sm)	:= $(cppflags$(sp-target)) -I$(sp-dev-kit-dir$(sm))/include
cflags$(sm)	:= $(cflags$(sp-target))
aflags$(sm)	:= $(aflags$(sp-target))

ifeq ($(CFG_ULIBS_SHARED),y)
# For now, do not link in-tree SPs against shared libraries
link-ldflags$(sm) := -static
endif

libdirs  = $(sp-dev-kit-dir$(sm))/lib
libnames = utils
libdeps = $(addsuffix .a, $(addprefix $(libdirs)/lib, $(libnames)))

subdirs = $(patsubst %/,%,$(dir $(sp-mk-file)))
include mk/subdir.mk

spec-out-dir := $(link-out-dir$(sm))
spec-srcs += $(sp-dev-kit-dir$(sm))/src/sp_assert.c
spec-srcs += $(sp-dev-kit-dir$(sm))/src/sp_entry.c
spec-srcs += $(sp-dev-kit-dir$(sm))/src/sp_header.c
spec-srcs += $(sp-dev-kit-dir$(sm))/src/sp_trace.c

# Install SP headers before in-tree SPs can be compiled
additional-compile-deps := $(sp_dev_kit-files-include)
include mk/compile.mk
# Install SP libraries before in-tree SPs can be linked
additional-link-deps := $(sp_dev_kit-files-lib)
include  sp/arch/$(ARCH)/link.mk

sp_dev_kit: $(out-dir)/export-$(sp-target)/sp/$(sp-uuid).sp

$(out-dir)/export-$(sp-target)/sp/$(sp-uuid).sp: $(link-out-dir$(sm))/$(sp-uuid).sp
	$(q)mkdir -p $(dir $@)
	@$(cmd-echo-silent) '  INSTALL $@'
	$(q)cp -P $< $@

cleanfiles += $(out-dir)/export-$(sp-target)/sp/$(sp-uuid).sp