

# Get the dir of the ta-dev-kit, requires make version 3.81 or later
ta-dev-kit-dir := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..))


.PHONY: all
all:

sm := user_ta
sm-$(ta) := y
binary := $(BINARY)

CROSS_COMPILE_$(sm)	?= $(CROSS_COMPILE)

ifneq ($O,)
out-dir := $O
else
out-dir := .
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


include $(ta-dev-kit-dir)/mk/arch.mk
-include $(ta-dev-kit-dir)/mk/platform_flags.mk

cppflags$(sm)  += $(platform-cppflags) $(user_ta-platform-cppflags)
aflags$(sm)    += $(platform-aflags) $(user_ta-platform-aflags)
cflags$(sm)    += $(platform-cflags) $(user_ta-platform-cflags)

CFG_TEE_TA_LOG_LEVEL ?= 2
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

CFG_TEE_CORE_USER_MEM_DEBUG ?= 0
cppflags$(sm) += -DCFG_TEE_CORE_USER_MEM_DEBUG=$(CFG_TEE_CORE_USER_MEM_DEBUG)

cppflags$(sm) += -I. -I$(ta-dev-kit-dir)/include

include $(ta-dev-kit-dir)/mk/arch.mk

libdirs += $(ta-dev-kit-dir)/lib
libnames += utee mpa utils utee
libdeps += $(ta-dev-kit-dir)/lib/libutils.a
libdeps += $(ta-dev-kit-dir)/lib/libmpa.a
libdeps += $(ta-dev-kit-dir)/lib/libutee.a

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   .'
	${q}rm -f $(cleanfiles)


subdirs = .
include  $(ta-dev-kit-dir)/mk/subdir.mk
vpath %.c $(ta-dev-kit-dir)/src
srcs += user_ta_header.c

include  $(ta-dev-kit-dir)/mk/gcc.mk
include  $(ta-dev-kit-dir)/mk/compile.mk
include  $(ta-dev-kit-dir)/mk/link.mk
