include mk/cleanvars.mk

# Set current submodule (used for module specific flags compile result etc)
sm := core
sm-$(sm) := y

arch-dir	:= core/arch/$(ARCH)
platform-dir	:= $(arch-dir)/plat-$(PLATFORM)
include $(platform-dir)/conf.mk
include mk/config.mk
# $(ARCH).mk also sets the compiler for the core module
include core/arch/$(ARCH)/$(ARCH).mk

ifeq ($(CFG_OS_REV_REPORTS_GIT_SHA1),y)
ifeq ($(arch-bits-core),64)
git-sha1-len := 16
else
git-sha1-len := 8
endif
TEE_IMPL_GIT_SHA1 := 0x$(shell git rev-parse --short=$(git-sha1-len) HEAD 2>/dev/null || echo 0 | cut -c -$(git-sha1-len))
else
TEE_IMPL_GIT_SHA1 := 0x0
endif

PLATFORM_$(PLATFORM) := y
PLATFORM_FLAVOR_$(PLATFORM_FLAVOR) := y

$(eval $(call cfg-depends-all,CFG_PAGED_USER_TA,CFG_WITH_PAGER CFG_WITH_USER_TA))
_CFG_CORE_ASYNC_NOTIF_DEFAULT_IMPL ?= $(CFG_CORE_ASYNC_NOTIF)
include core/crypto.mk

ifeq ($(CFG_SCMI_SCPFW),y)
include core/lib/scmi-server/conf.mk
endif

cppflags$(sm)	+= -D__KERNEL__

cppflags$(sm)	+= -Icore/include
cppflags$(sm)	+= -include $(conf-file)
cppflags$(sm)	+= -I$(out-dir)/core/include
cppflags$(sm)	+= $(core-platform-cppflags)
cflags$(sm)	+= $(core-platform-cflags)

core-stackp-cflags-$(CFG_CORE_STACK_PROTECTOR) := -fstack-protector
core-stackp-cflags-$(CFG_CORE_STACK_PROTECTOR_STRONG) := -fstack-protector-strong
core-stackp-cflags-$(CFG_CORE_STACK_PROTECTOR_ALL) := -fstack-protector-all
cflags$(sm)	+= $(core-stackp-cflags-y)

ifeq ($(CFG_CORE_SANITIZE_UNDEFINED),y)
cflags$(sm)	+= -fsanitize=undefined
endif
ifeq ($(CFG_CORE_SANITIZE_KADDRESS),y)
ifeq ($(CFG_ASAN_SHADOW_OFFSET),)
$(error error: CFG_CORE_SANITIZE_KADDRESS not supported by platform (flavor))
endif
ifeq ($(COMPILER),clang)
$(error error: CFG_CORE_SANITIZE_KADDRESS not supported with Clang)
endif
cflags_kasan	+= -fsanitize=kernel-address \
		   -fasan-shadow-offset=$(CFG_ASAN_SHADOW_OFFSET)\
		   --param asan-stack=1 --param asan-globals=1 \
		   --param asan-instrumentation-with-call-threshold=0
cflags$(sm)	+= $(cflags_kasan)
endif
ifeq ($(CFG_CORE_DEBUG_CHECK_STACKS),y)
finstrument-functions := $(call cc-option,-finstrument-functions)
ifeq (,$(finstrument-functions))
$(error -finstrument-functions not supported)
endif
cflags$(sm) += $(finstrument-functions)
endif
ifeq ($(CFG_SYSCALL_FTRACE),y)
cflags$(sm)	+= -pg
endif
aflags$(sm)	+= $(core-platform-aflags)

cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_CORE_LOG_LEVEL)
ifeq ($(CFG_TEE_CORE_MALLOC_DEBUG),y)
cppflags$(sm) += -DENABLE_MDBG=1
endif
ifneq ($(CFG_TEE_CORE_DEBUG),y)
cppflags$(sm)  += -DNDEBUG
endif

cppflags$(sm)	+= -Ildelf/include
cppflags$(sm)	+= -Ilib/libutee/include

ifeq ($(filter y, $(CFG_CORE_DYN_SHM) $(CFG_CORE_RESERVED_SHM)),)
$(error error: No shared memory configured)
endif

# Tell all libraries and sub-directories (included below) that we have a
# configuration file

conf-file := $(out-dir)/include/generated/conf.h
conf-mk-file := $(out-dir)/conf.mk
conf-cmake-file := $(out-dir)/conf.cmake
$(conf-file): $(conf-mk-file)

cleanfiles += $(conf-file)
cleanfiles += $(conf-mk-file)
cleanfiles += $(conf-cmake-file)

$(conf-file): FORCE
	$(call check-conf-h)

$(conf-mk-file):  FORCE
	$(call check-conf-mk)

$(conf-cmake-file):  FORCE
	$(call check-conf-cmake)

#
# Do libraries
#

# Set a prefix to avoid conflicts with user TAs that will use the same
# source but with different flags below
base-prefix := $(sm)-
libname = utils
libdir = lib/libutils
include mk/lib.mk

# CFG_CRYPTOLIB_NAME must not be changed beyond this line
CFG_CRYPTOLIB_NAME_$(CFG_CRYPTOLIB_NAME) := y

ifeq ($(CFG_CRYPTOLIB_NAME),tomcrypt)
# We're compiling mbedtls too, but with a limited configuration which only
# provides the MPI routines
libname = mbedtls
libdir = lib/libmbedtls
include mk/lib.mk
endif #tomcrypt

ifeq ($(CFG_CRYPTOLIB_NAME),mbedtls)
$(call force,CFG_CRYPTO_RSASSA_NA1,n,not supported by mbedtls)
libname = tomcrypt
libdir = core/lib/libtomcrypt
base-prefix :=
include mk/lib.mk
base-prefix := $(sm)-
endif

ifeq ($(firstword $(subst /, ,$(CFG_CRYPTOLIB_DIR))),core)
# If a library can be compiled for both core and user space a base-prefix
# is needed in order to avoid conflicts in the output. However, if the
# library resides under core then it can't be compiled to user space.
base-prefix :=
endif

libname = $(CFG_CRYPTOLIB_NAME)
libdir = $(CFG_CRYPTOLIB_DIR)
include mk/lib.mk

base-prefix :=

libname = fdt
libdir = core/lib/libfdt
include mk/lib.mk

ifeq ($(CFG_ZLIB),y)
libname = zlib
libdir = core/lib/zlib
include mk/lib.mk
endif

libname = unw
libdir = lib/libunw
include mk/lib.mk

ifeq ($(CFG_SCMI_SCPFW),y)
libname = scmi-server
libdir = core/lib/scmi-server
include mk/lib.mk
endif

#
# Do main source
#

subdirs = $(core-platform-subdirs) core
include mk/subdir.mk

include mk/compile.mk

include $(if $(wildcard $(platform-dir)/link.mk), \
		$(platform-dir)/link.mk, \
		core/arch/$(ARCH)/kernel/link.mk)
