# Get the dir of the ta-dev-kit, requires make version 3.81 or later
ta-dev-kit-dir := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..))

.PHONY: all
all:

include $(ta-dev-kit-dir)/mk/conf.mk
ta-dev-kit-dir$(sm) := $(ta-dev-kit-dir)

ifneq (1, $(words $(BINARY) $(LIBNAME) $(SHLIBNAME)))
$(error You must specify exactly one of BINARY, LIBNAME or SHLIBNAME)
endif

ifneq ($O,)
out-dir := $O
else
out-dir := .
endif
link-out-dir := $(out-dir)	# backward compat
link-out-dir$(sm) := $(out-dir)

user-ta-uuid := $(BINARY)
user-ta-version := $(if $(CFG_TA_VERSION),$(CFG_TA_VERSION),0)
user-ta-ldadd := $(LDADD)
libname := $(LIBNAME)
shlibname := $(SHLIBNAME)
shlibuuid := $(SHLIBUUID)

arch-bits-ta_arm32 := 32
arch-bits-ta_arm64 := 64

# For convenience
ifdef CFLAGS
CFLAGS32 ?= $(CFLAGS)
CFLAGS64 ?= $(CFLAGS)
endif

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
ifneq (,$(shlibname))
# Exception handling is not supported in shared libraries (with GCC it would
# require to use the shared libgcc, which depend on the GNU libc)
cxxflags$(sm)  += -fno-exceptions
endif

CFG_TEE_TA_LOG_LEVEL ?= 2
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

cppflags$(sm) += -I. -I$(ta-dev-kit-dir$(sm))/include

ifeq ($(CFG_TA_MCOUNT),y)
cppflags$(sm) += -pg
endif

libdirs += $(ta-dev-kit-dir$(sm))/lib
libnames += utils
libdeps += $(ta-dev-kit-dir$(sm))/lib/libutils.a
libnames += utee
libdeps += $(ta-dev-kit-dir$(sm))/lib/libutee.a
ifeq ($(CFG_TA_MBEDTLS),y)
libnames += mbedtls
libdeps += $(ta-dev-kit-dir$(sm))/lib/libmbedtls.a
endif
libnames += dl
libdeps += $(ta-dev-kit-dir$(sm))/lib/libdl.a

# libutils provides __getauxval symbol which is needed by libgcc 10.x. We can't
# link libutils after libgcc, because libgcc will replace some symbols provided
# by libutils, which will cause further linking issues.
#
# But if we place libutils before libgcc, linker will not be able to resolve
# __getauxval. So we need to link with libutils twice: before and after libgcc.
# Hence it included both in $(libnames) and in $(libnames-after-libgcc)
libnames-after-libgcc += utils
libdeps-after-libgcc += $(ta-dev-kit-dir$(sm))/lib/libutils.a

# Pass config variable (CFG_) from conf.mk on the command line
cppflags$(sm) += $(strip \
	$(foreach var, $(filter CFG_%,$(.VARIABLES)), \
		$(if $(filter y,$($(var))), \
			-D$(var)=1, \
			$(if $(filter xn x,x$($(var))),,-D$(var)='$($(var))'))))

include $(ta-dev-kit-dir$(sm))/mk/cleandirs.mk

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   $(out-dir)'
	${q}rm -f $(cleanfiles)
	${q}dirs="$(call cleandirs-for-rmdir)"; if [ "$$dirs" ]; then $(RMDIR) $$dirs; fi
	@$(cmd-echo-silent) '  CLEAN   $(O)'
	${q}if [ -d "$(O)" ]; then $(RMDIR) $(O); fi

include  $(ta-dev-kit-dir$(sm))/mk/$(COMPILER_$(sm)).mk
include  $(ta-dev-kit-dir$(sm))/mk/cc-option.mk

subdirs = .
include  $(ta-dev-kit-dir$(sm))/mk/subdir.mk

ifneq ($(user-ta-uuid),)
# Build target is TA
vpath %.c $(ta-dev-kit-dir$(sm))/src
srcs += user_ta_header.c
ifeq ($(sm),ta_arm32)
vpath %.S $(ta-dev-kit-dir$(sm))/src
srcs += ta_entry_a32.S
endif
endif

SCRIPTS_DIR := $(ta-dev-kit-dir)/scripts
include  $(ta-dev-kit-dir$(sm))/mk/compile.mk

ifneq ($(user-ta-uuid),)
include  $(ta-dev-kit-dir$(sm))/mk/link.mk
endif

ifneq ($(libname),)
# Build target is static library
all: $(libname).a
cleanfiles += $(libname).a

$(libname).a: $(objs)
	@echo '  AR      $@'
	$(q)rm -f $@ && $(AR$(sm)) rcs $@ $^
endif

ifneq (,$(shlibname))
include $(ta-dev-kit-dir$(sm))/mk/link_shlib.mk
endif
