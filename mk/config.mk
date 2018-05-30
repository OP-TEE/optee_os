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

# Log levels for the TEE core and user-mode TAs
# Defines which messages are displayed on the secure console
# 0: none
# 1: error
# 2: error + warning
# 3: error + warning + debug
# 4: error + warning + debug + flow
CFG_TEE_CORE_LOG_LEVEL ?= 1
CFG_TEE_TA_LOG_LEVEL ?= 1

# TA enablement
# When defined to "y", TA traces are output according to
# CFG_TEE_TA_LOG_LEVEL. Otherwise, they are not output at all
CFG_TEE_CORE_TA_TRACE ?= y

# If y, enable the memory leak detection feature in the bget memory allocator.
# When this feature is enabled, calling mdbg_check(1) will print a list of all
# the currently allocated buffers and the location of the allocation (file and
# line number).
# Note: make sure the log level is high enough for the messages to show up on
# the secure console! For instance:
# - To debug user-mode (TA) allocations: build OP-TEE *and* the TA with:
#   $ make CFG_TEE_TA_MALLOC_DEBUG=y CFG_TEE_TA_LOG_LEVEL=3
# - To debug TEE core allocations: build OP-TEE with:
#   $ make CFG_TEE_CORE_MALLOC_DEBUG=y CFG_TEE_CORE_LOG_LEVEL=3
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

# Should OPTEE_SMC_CALL_GET_OS_REVISION return a build identifier to Normal
# World?
CFG_OS_REV_REPORTS_GIT_SHA1 ?= y

# Trusted OS implementation version
TEE_IMPL_VERSION ?= $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)
ifeq ($(CFG_OS_REV_REPORTS_GIT_SHA1),y)
TEE_IMPL_GIT_SHA1 := 0x$(shell git rev-parse --short=8 HEAD 2>/dev/null || echo 0)
else
TEE_IMPL_GIT_SHA1 := 0x0
endif
# The following values are not extracted from the "git describe" output because
# we might be outside of a Git environment, or the tree may have been cloned
# with limited depth not including any tag, so there is really no guarantee
# that TEE_IMPL_VERSION contains the major and minor revision numbers.
CFG_OPTEE_REVISION_MAJOR ?= 3
CFG_OPTEE_REVISION_MINOR ?= 1

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

# Stack unwinding: print a stack dump to the console on core or TA abort, or
# when a TA panics.
# If CFG_UNWIND is enabled, both the kernel and user mode call stacks can be
# unwound (not paged TAs, however).
# Note that 32-bit ARM code needs unwind tables for this to work, so enabling
# this option will increase the size of the 32-bit TEE binary by a few KB.
# Similarly, TAs have to be compiled with -funwind-tables (default when the
# option is set) otherwise they can't be unwound.
# Warning: since the unwind sequence for user-mode (TA) code is implemented in
# the privileged layer of OP-TEE, enabling this feature will weaken the
# user/kernel isolation. Therefore it should be disabled in release builds.
ifeq ($(CFG_TEE_CORE_DEBUG),y)
CFG_UNWIND ?= y
endif

# Enable support for dynamically loaded user TAs
CFG_WITH_USER_TA ?= y

# Load user TAs from the REE filesystem via tee-supplicant
# There is currently no other alternative, but you may want to disable this in
# case you implement your own TA store
CFG_REE_FS_TA ?= y

# Support for loading user TAs from a special section in the TEE binary.
# Such TAs are available even before tee-supplicant is available (hence their
# name), but note that many services exported to TAs may need tee-supplicant,
# so early use is limited to a subset of the TEE Internal Core API (crypto...)
# To use this feature, set EARLY_TA_PATHS to the paths to one or more TA ELF
# file(s). For example:
#   $ make ... \
#     EARLY_TA_PATHS="path/to/8aaaf200-2450-11e4-abe2-0002a5d5c51b.stripped.elf \
#                     path/to/cb3e5ba0-adf1-11e0-998b-0002a5d5c51b.stripped.elf"
# Typical build steps:
#   $ make ta_dev_kit CFG_EARLY_TA=y # Create the dev kit (user mode libraries,
#                                    # headers, makefiles), ready to build TAs.
#                                    # CFG_EARLY_TA=y is optional, it prevents
#                                    # later library recompilations.
#   <build some TAs>
#   $ make EARLY_TA_PATHS=<paths>    # Build OP-TEE and embbed the TA(s)
ifneq ($(EARLY_TA_PATHS),)
$(call force,CFG_EARLY_TA,y)
else
CFG_EARLY_TA ?= n
endif
ifeq ($(CFG_EARLY_TA),y)
$(call force,CFG_ZLIB,y)
endif

# Support for dynamically linked user TAs
CFG_TA_DYNLINK ?= y

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

# Enable core self tests and related pseudo TAs
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

# Enable storage for TAs in secure storage, depends on CFG_REE_FS=y
# TA binaries are stored encrypted in the REE FS and are protected by
# metadata in secure storage.
CFG_SECSTOR_TA ?= $(call cfg-all-enabled,CFG_REE_FS CFG_WITH_USER_TA)
$(eval $(call cfg-depends-all,CFG_SECSTOR_TA,CFG_REE_FS CFG_WITH_USER_TA))

# Enable the pseudo TA that managages TA storage in secure storage
CFG_SECSTOR_TA_MGMT_PTA ?= $(call cfg-all-enabled,CFG_SECSTOR_TA)
$(eval $(call cfg-depends-all,CFG_SECSTOR_TA_MGMT_PTA,CFG_SECSTOR_TA))

# Enable the pseudo TA for misc. auxilary services, extending existing
# GlobalPlatform Core API (for example, re-seeding RNG entropy pool etc.)
CFG_SYSTEM_PTA ?= y

# Define the number of cores per cluster used in calculating core position.
# The cluster number is shifted by this value and added to the core ID,
# so its value represents log2(cores/cluster).
# Default is 2**(2) = 4 cores per cluster.
CFG_CORE_CLUSTER_SHIFT ?= 2

# Do not report to NW that dynamic shared memory (shared memory outside
# predefined region) is enabled.
# Note that you can disable this feature for debug purposes. OP-TEE will not
# report to Normal World that it support dynamic SHM. But, nevertheles it
# will accept dynamic SHM buffers.
CFG_DYN_SHM_CAP ?= y

# Enables support for larger physical addresses, that is, it will define
# paddr_t as a 64-bit type.
CFG_CORE_LARGE_PHYS_ADDR ?= n

# Define the maximum size, in bits, for big numbers in the Internal Core API
# Arithmetical functions. This does *not* influence the key size that may be
# manipulated through the Cryptographic API.
# Set this to a lower value to reduce the TA memory footprint.
CFG_TA_BIGNUM_MAX_BITS ?= 2048

# Define the maximum size, in bits, for big numbers in the TEE core (privileged
# layer).
# This value is an upper limit for the key size in any cryptographic algorithm
# implemented by the TEE core.
# Set this to a lower value to reduce the memory footprint.
CFG_CORE_BIGNUM_MAX_BITS ?= 4096

# Compiles mbedTLS for TA usage
CFG_TA_MBEDTLS ?= y

# Compile the TA library mbedTLS with self test functions, the functions
# need to be called to test anything
CFG_TA_MBEDTLS_SELF_TEST ?= y
