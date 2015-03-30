include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := core
sm-$(sm) := y

arch-dir	:= core/arch/$(ARCH)
platform-dir	:= $(arch-dir)/plat-$(PLATFORM)
include $(platform-dir)/conf.mk
include core/arch/$(ARCH)/$(ARCH).mk

# Setup compiler for this sub module
CROSS_COMPILE_$(sm)	?= $(CROSS_COMPILE)
COMPILER_$(sm)		?= $(COMPILER)
include mk/$(COMPILER_$(sm)).mk

PLATFORM_FLAVOR ?= default
platform_$(PLATFORM) := y
platform_flavor_$(PLATFORM_FLAVOR) := y
cppflags$(sm)	+= -DPLATFORM_FLAVOR=PLATFORM_FLAVOR_ID_$(PLATFORM_FLAVOR)

cppflags$(sm)	+= -Icore/include
cppflags$(sm)	+= -include $(out-dir)/core/include/generated/conf.h
cppflags$(sm)	+= $(platform-cppflags) $(core-platform-cppflags)
cflags$(sm)	+= $(platform-cflags) $(core-platform-cflags)
aflags$(sm)	+= $(platform-aflags) $(core-platform-aflags)

# Config flags from mk/config.mk
cppflags$(sm) += -DCFG_TEE_FW_DEBUG=$(CFG_TEE_FW_DEBUG)
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_CORE_LOG_LEVEL)

cppflags$(sm)	+= -Ilib/libutee/include

# Tell all libraries and sub-directories (included below) that we have a
# configuration file

conf-file := $(out-dir)/core/include/generated/conf.h
conf-mk-file := $(out-dir)/core/conf.mk
$(conf-file): $(conf-mk-file)

cleanfiles += $(conf-file)
cleanfiles += $(conf-mk-file)

include mk/checkconf.mk
$(conf-file): FORCE
	$(call check-conf-h)

$(conf-mk-file):  FORCE
	$(call build-conf-mk)

#
# Do libraries
#

# Set a prefix to avoid conflicts with user TAs that will use the same
# source but with different flags below
base-prefix := $(sm)-
libname = utils
libdir = lib/libutils
include mk/lib.mk

libname = mpa
libdir = lib/libmpa
include mk/lib.mk
base-prefix :=

libname = tomcrypt
libdir = core/lib/libtomcrypt
include mk/lib.mk

#
# Do main source
#
subdirs = $(core-platform-subdirs) core
include mk/subdir.mk
include mk/compile.mk
include $(platform-dir)/link.mk


