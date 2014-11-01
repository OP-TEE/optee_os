

# Get the dir of the ta-dev-kit, requires make version 3.81 or later
ta-dev-kit-dir := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..))


.PHONY: all
all:

sm := ta
sm-$(ta) := y
binary := $(BINARY)

ifneq ($O,)
out-dir := $O
else
out-dir := .
endif

ifneq ($V,1)
q := @
cmd-echo := true
else
q :=
cmd-echo := echo
endif

cflags$(sm) += -fno-short-enums -fpie -mfloat-abi=soft
cppflags$(sm) += -I. -I$(ta-dev-kit-dir)/include

ifeq ($(DEBUG),1)
cflags$(sm) += -O0
else
cflags$(sm) += -Os
endif
cflags$(sm) += -g -g3
aflags$(sm) += -g -g3


libdirs += $(ta-dev-kit-dir)/lib
libnames += utils mpa utee
libdeps += $(ta-dev-kit-dir)/lib/libutils.a
libdeps += $(ta-dev-kit-dir)/lib/libmpa.a
libdeps += $(ta-dev-kit-dir)/lib/libutee.a

.PHONY: clean
clean:
	@echo '  CLEAN   .'
	${q}rm -f $(cleanfiles)


subdirs = .
include  $(ta-dev-kit-dir)/mk/subdir.mk
vpath %.c $(ta-dev-kit-dir)/src
srcs += user_ta_header.c

include  $(ta-dev-kit-dir)/mk/gcc.mk
include  $(ta-dev-kit-dir)/mk/compile.mk
include  $(ta-dev-kit-dir)/mk/link.mk
