# Default configuration values for OP-TEE core (all platforms).
#
# Platform-specific overrides are in core/arch/arm32/plat-*/conf.mk.
# Some subsystem-specific defaults are not here but rather in */sub.mk.
#
# Configuration values may be assigned from multiple sources.
# From higher to lower priority:
#
#   1. Make arguments ('make CFG_FOO=bar...')
#   2. The file specified by $(CFG_OPTEE_CONFIG) (if defined)
#   3. The environment ('CFG_FOO=bar make...')
#   4. The platform-specific configuration file: core/arch/arm32/plat-*/conf.mk
#   5. This file
#   6. Subsystem-specific makefiles (*/sub.mk)
#
# Actual values used during the build are output to $(out-dir)/conf.mk
# (CFG_* variables only).

# Cross-compiler prefix and suffix
CROSS_COMPILE ?= arm-linux-gnueabihf-
CROSS_COMPILE32 ?= $(CROSS_COMPILE)
CROSS_COMPILE64 ?= aarch64-linux-gnu-
COMPILER ?= gcc

# For convenience
ifdef CFLAGS
CFLAGS32 ?= $(CFLAGS)
CFLAGS64 ?= $(CFLAGS)
endif

# Compiler warning level.
# Supported values: undefined, 1, 2 and 3. 3 gives more warnings.
WARNS ?= 3

# Define NOWERROR=1 so that warnings are not treated as errors
# NOWERROR=1

# Define DEBUG=1 to compile with -g option
# DEBUG=1

# If 1, debug mode of the tee firmware (CPU restart, Core Status)
CFG_TEE_CORE_DEBUG ?= 0

# Max level of the tee core traces. 0 means disable, 4 is max.
# Supported values: 0 (no traces) to 4 (all traces)
# If CFG_TEE_DRV_DEBUGFS is set, the level of traces to print can be
# dynamically changes via debugfs in the range 1 => CFG_TEE_CORE_LOG_LEVEL
CFG_TEE_CORE_LOG_LEVEL ?= 1

# TA and TEECore log level
# Supported values: 0 (no traces) to 4 (all traces)
# If CFG_TEE_DRV_DEBUGFS is set, the level of traces to print can be
# dynamically changes via debugfs in the range 1 => CFG_TEE_TA_LOG_LEVEL
CFG_TEE_TA_LOG_LEVEL ?= 1

# TA enablement
# When defined to "y", TA traces are output according to
# CFG_TEE_TA_LOG_LEVEL. Otherwise, they are not output at all
CFG_TEE_CORE_TA_TRACE ?= y

# Define TEE_Panic as a macro to help debugging panics caused by calls to
# TEE_Panic. This flag can have a different value when later compiling the
# TA
CFG_TEE_PANIC_DEBUG ?= y

# If 1, enable debug features in TA memory allocation.
# Debug features include check of buffer overflow, statistics, mark/check heap
# feature.
CFG_TEE_CORE_USER_MEM_DEBUG ?= 1

# If y, enable memory leak detection feature in bget memory allocator.
CFG_TEE_CORE_MALLOC_DEBUG ?= n
CFG_TEE_TA_MALLOC_DEBUG ?= n

# PRNG configuration
# If CFG_WITH_SOFTWARE_PRNG is enabled, crypto provider provided
# software PRNG implementation is used.
# Otherwise, you need to implement hw_get_random_byte() for your platform
CFG_WITH_SOFTWARE_PRNG ?= y

# Number of threads
CFG_NUM_THREADS ?= 2

# API implementation version
CFG_TEE_API_VERSION ?= GPD-1.1-dev

# Implementation description (implementation-dependent)
CFG_TEE_IMPL_DESCR ?= OPTEE

# Trusted OS implementation version
TEE_IMPL_VERSION ?= $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)
# The following values are not extracted from the "git describe" output because
# we might be outside of a Git environment, or the tree may have been cloned
# with limited depth not including any tag, so there is really no guarantee
# that TEE_IMPL_VERSION contains the major and minor revision numbers.
CFG_OPTEE_REVISION_MAJOR ?= 2
CFG_OPTEE_REVISION_MINOR ?= 0

# Trusted OS implementation manufacturer name
CFG_TEE_MANUFACTURER ?= LINARO

# Trusted firmware version
CFG_TEE_FW_IMPL_VERSION ?= FW_IMPL_UNDEF

# Trusted OS implementation manufacturer name
CFG_TEE_FW_MANUFACTURER ?= FW_MAN_UNDEF

# Encrypted File System Support
# Applies to both the default and the RPMB filesystems
CFG_ENC_FS ?= y

# File System Block Cache Support
# Does not apply to the RPMB FS
CFG_FS_BLOCK_CACHE ?= n

# RPMB file system support
# When enabled, replaces the default (REE-based) FS
CFG_RPMB_FS ?= n

# Device identifier used when CFG_RPMB_FS = y.
# The exact meaning of this value is platform-dependent. On Linux, the
# tee-supplicant process will open /dev/mmcblk<id>rpmb
CFG_RPMB_FS_DEV_ID ?= 0

# Embed public part of this key in OP-TEE OS
TA_SIGN_KEY ?= keys/default_ta.pem

# Include lib/libutils/isoc in the build? Most platforms need this, but some
# may not because they obtain the isoc functions from elsewhere
CFG_LIBUTILS_WITH_ISOC ?= y

# Enables floating point support for user TAs
# ARM32: EABI defines both a soft-float ABI and a hard-float ABI,
#	 hard-float is basically a super set of soft-float. Hard-float
#	 requires all the support routines provided for soft-float, but the
#	 compiler may choose to optimize to not use some of them and use
#	 the floating-point registers instead.
# ARM64: EABI doesn't define a soft-float ABI, everything is hard-float (or
#	 nothing with ` -mgeneral-regs-only`)
# With CFG_TA_FLOAT_SUPPORT enabled TA code is free use floating point types
CFG_TA_FLOAT_SUPPORT ?= y

# Enable stack unwinding for aborts from kernel mode if CFG_TEE_CORE_DEBUG
# is enabled
ifeq ($(CFG_TEE_CORE_DEBUG),1)
CFG_CORE_UNWIND ?= y
endif

# Enable support for dynamically loaded user TAs
CFG_WITH_USER_TA ?= y

# Use small pages to map user TAs
CFG_SMALL_PAGE_USER_TA ?= y
