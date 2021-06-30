# Get the dir of the sp-dev-kit, requires make version 3.81 or later
sp-dev-kit-dir := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..))

.PHONY: all
all:

include $(sp-dev-kit-dir)/mk/conf.mk
sp-dev-kit-dir$(sm) := $(sp-dev-kit-dir)

ifneq (1, $(words $(BINARY)))
$(error You must specify the BINARY variable)
endif

ifneq ($O,)
out-dir := $O
else
out-dir := .
endif
link-out-dir := $(out-dir)	# backward compat
link-out-dir$(sm) := $(out-dir)

sp-uuid := $(BINARY)
sp-version := $(if $(CFG_SP_VERSION),$(CFG_SP_VERSION),0)
sp-ldadd := $(LDADD)
libname := $(LIBNAME)
shlibname := $(SHLIBNAME)
shlibuuid := $(SHLIBUUID)


ifneq ($V,1)
q := @
cmd-echo := true
cmd-echo-silent := echo
else
q :=
cmd-echo := echo
cmd-echo-silent := true
endif

ifneq ($(filter 4.%,$(MAKE_VERSION)),)  # make-4
ifneq ($(filter %s ,$(firstword x$(MAKEFLAGS))),)
cmd-echo-silent := true
endif
else                                    # make-3.8x
ifneq ($(findstring s, $(MAKEFLAGS)),)
cmd-echo-silent := true
endif
endif

cppflags$(sm)  := $($(sm)-platform-cppflags) $(CPPFLAGS_$(sm))
aflags$(sm)    := $($(sm)-platform-aflags)
cflags$(sm)    := $($(sm)-platform-cflags) $(CFLAGS_$(sm))
cxxflags$(sm)  := $($(sm)-platform-cxxflags) $(CXXFLAGS_$(sm))

CFG_TEE_SP_LOG_LEVEL ?= 2
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_SP_LOG_LEVEL)

cppflags$(sm) += -I. -I$(sp-dev-kit-dir$(sm))/include

libdirs += $(sp-dev-kit-dir$(sm))/lib
libnames += utils
libdeps += $(sp-dev-kit-dir$(sm))/lib/libutils.a

# libutils provides __getauxval symbol which is needed by libgcc 10.x. We can't
# link libutils after libgcc, because libgcc will replace some symbols provided
# by libutils, which will cause further linking issues.
#
# But if we place libutils before libgcc, linker will not be able to resolve
# __getauxval. So we need to link with libutils twice: before and after libgcc.
# Hence it included both in $(libnames) and in $(libnames-after-libgcc)
libnames-after-libgcc += utils
libdeps-after-libgcc += $(sp-dev-kit-dir$(sm))/lib/libutils.a

# Pass config variable (CFG_) from conf.mk on the command line
cppflags$(sm) += $(strip \
	$(foreach var, $(filter CFG_%,$(.VARIABLES)), \
		$(if $(filter y,$($(var))), \
			-D$(var)=1, \
			$(if $(filter xn x,x$($(var))),,-D$(var)='$($(var))'))))

include $(sp-dev-kit-dir$(sm))/mk/cleandirs.mk

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   $(out-dir)'
	${q}rm -f $(cleanfiles)
	${q}dirs="$(call cleandirs-for-rmdir)"; if [ "$$dirs" ]; then $(RMDIR) $$dirs; fi
	@$(cmd-echo-silent) '  CLEAN   $(O)'
	${q}if [ -d "$(O)" ]; then $(RMDIR) $(O); fi

include  $(sp-dev-kit-dir$(sm))/mk/$(COMPILER_$(sm)).mk
include  $(sp-dev-kit-dir$(sm))/mk/cc-option.mk

subdirs = .
include  $(sp-dev-kit-dir$(sm))/mk/subdir.mk

ifneq ($(sp-uuid),)
# Build target is SP
vpath %.c $(sp-dev-kit-dir$(sm))/src
srcs += sp_assert.c
srcs += sp_entry.c
srcs += sp_header.c
srcs += sp_trace.c
ifeq ($(sm),sp_arm32)
vpath %.S $(sp-dev-kit-dir$(sm))/src
srcs += sp_entry_a32.S
endif
endif

SCRIPTS_DIR := $(sp-dev-kit-dir)/scripts
include  $(sp-dev-kit-dir$(sm))/mk/compile.mk

ifneq ($(sp-uuid),)
include  $(sp-dev-kit-dir$(sm))/mk/link.mk
endif
