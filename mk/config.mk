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

# Define DEBUG=1 to compile without optimization (forces -O0)
# DEBUG=1

# If y, enable debug features of the TEE core (assertions and lock checks
# are enabled, panic and assert messages are more verbose, data and prefetch
# aborts show a stack dump). When disabled, the NDEBUG directive is defined
# so assertions are disabled.
CFG_TEE_CORE_DEBUG ?= y

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

# Mask to select which messages are prefixed with long debugging information
# (severity, thread ID, component name, function name, line number) based on
# the message level. If BIT(level) is set, the long prefix is shown.
# Otherwise a short prefix is used (severity and component name only).
# Levels: 0=none 1=error 2=info 3=debug 4=flow
CFG_MSG_LONG_PREFIX_MASK ?= 0x1a

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
CFG_OPTEE_REVISION_MINOR ?= 5

# Trusted OS implementation manufacturer name
CFG_TEE_MANUFACTURER ?= LINARO

# Trusted firmware version
CFG_TEE_FW_IMPL_VERSION ?= FW_IMPL_UNDEF

# Trusted OS implementation manufacturer name
CFG_TEE_FW_MANUFACTURER ?= FW_MAN_UNDEF

# Rich Execution Environment (REE) file system support: normal world OS
# provides the actual storage.
# This is the default FS when enabled (i.e., the one used when
# TEE_STORAGE_PRIVATE is passed to the trusted storage API)
CFG_REE_FS ?= y

# RPMB file system support
CFG_RPMB_FS ?= n

# Device identifier used when CFG_RPMB_FS = y.
# The exact meaning of this value is platform-dependent. On Linux, the
# tee-supplicant process will open /dev/mmcblk<id>rpmb
CFG_RPMB_FS_DEV_ID ?= 0

# Enables RPMB key programming by the TEE, in case the RPMB partition has not
# been configured yet.
# !!! Security warning !!!
# Do *NOT* enable this in product builds, as doing so would allow the TEE to
# leak the RPMB key.
# This option is useful in the following situations:
# - Testing
# - RPMB key provisioning in a controlled environment (factory setup)
CFG_RPMB_WRITE_KEY ?= n

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

# Stack unwinding: print a stack dump to the console on abort
# If CFG_UNWIND is enabled, both the kernel and user mode call stacks can be
# unwound (not paged TAs, however).
# Note that 32-bit ARM code needs unwind tables for this to work, so enabling
# this option will increase the size of the 32-bit TEE binary by a few KB.
# Similarly, TAs have to be compiled with -funwind-tables (default when the
# option is set) otherwise they can't be unwound.
ifeq ($(CFG_TEE_CORE_DEBUG),y)
CFG_UNWIND ?= y
endif

# Enable support for dynamically loaded user TAs
CFG_WITH_USER_TA ?= y

# Load user TAs from the REE filesystem via tee-supplicant
# There is currently no other alternative, but you may want to disable this in
# case you implement your own TA store
CFG_REE_FS_TA ?= y

# Enable paging, requires SRAM, can't be enabled by default
CFG_WITH_PAGER ?= n

# Use the pager for user TAs
CFG_PAGED_USER_TA ?= $(CFG_WITH_PAGER)

# Enable support for detected undefined behavior in C
# Uses a lot of memory, can't be enabled by default
CFG_CORE_SANITIZE_UNDEFINED ?= n

# Enable Kernel Address sanitizer, has a huge performance impact, uses a
# lot of memory and need platform specific adaptations, can't be enabled by
# default
CFG_CORE_SANITIZE_KADDRESS ?= n

# Device Tree support
# When enabled, the TEE _start function expects to find the address of a
# Device Tree Blob (DTB) in register r2. The DT parsing code relies on
# libfdt.  Currently only used to add the optee node and a reserved-memory
# node for shared memory.
CFG_DT ?= n

# Maximum size of the Device Tree Blob, has to be large enough to allow
# editing of the supplied DTB.
CFG_DTB_MAX_SIZE ?= 0x10000

# Enable static TA and core self tests
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y

# This option enables OP-TEE to respond to SMP boot request: the Rich OS
# issues this to request OP-TEE to release secondaries cores out of reset,
# with specific core number and non-secure entry address.
CFG_BOOT_SECONDARY_REQUEST ?= n

# Default heap size for Core, 64 kB
CFG_CORE_HEAP_SIZE ?= 65536

# TA profiling.
# When this option is enabled, OP-TEE can execute Trusted Applications
# instrumented with GCC's -pg flag and will output profiling information
# in gmon.out format to /tmp/gmon-<ta_uuid>.out (path is defined in
# tee-supplicant)
CFG_TA_GPROF_SUPPORT ?= n

# Enable to compile user TA libraries with profiling (-pg).
# Depends on CFG_TA_GPROF_SUPPORT.
CFG_ULIBS_GPROF ?= n

ifeq ($(CFG_ULIBS_GPROF),y)
ifneq ($(CFG_TA_GPROF_SUPPORT),y)
$(error Cannot instrument user libraries if user mode profiling is disabled)
endif
endif

# CFG_GP_SOCKETS
# Enable Global Platform Sockets support
CFG_GP_SOCKETS ?= y

# Enable Secure Data Path support in OP-TEE core (TA may be invoked with
# invocation parameters referring to specific secure memories).
CFG_SECURE_DATA_PATH ?= n
