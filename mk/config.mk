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

# Path to the Python interpreter used by the build system.
# This variable is set to the default python3 interpreter in the user's
# path. But build environments that require more explicit control can
# set the path to a specific interpreter through this variable.
PYTHON3 ?= python3

# Define DEBUG=1 to compile without optimization (forces -O0)
# DEBUG=1

# If y, enable debug features of the TEE core (assertions and lock checks
# are enabled, panic and assert messages are more verbose, data and prefetch
# aborts show a stack dump). When disabled, the NDEBUG directive is defined
# so assertions are disabled.
CFG_TEE_CORE_DEBUG ?= y

# Log levels for the TEE core. Defines which core messages are displayed
# on the secure console. Disabling core log (level set to 0) also disables
# logs from the TAs.
# 0: none
# 1: error
# 2: error + warning
# 3: error + warning + debug
# 4: error + warning + debug + flow
CFG_TEE_CORE_LOG_LEVEL ?= 1

# TA log level
# If user-mode library libutils.a is built with CFG_TEE_TA_LOG_LEVEL=0,
# TA tracing is disabled regardless of the value of CFG_TEE_TA_LOG_LEVEL
# when the TA is built.
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
# Prints an error message and dumps the stack on failed memory allocations
# using malloc() and friends.
CFG_CORE_DUMP_OOM ?= $(CFG_TEE_CORE_MALLOC_DEBUG)

# Mask to select which messages are prefixed with long debugging information
# (severity, core ID, thread ID, component name, function name, line number)
# based on the message level. If BIT(level) is set, the long prefix is shown.
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
CFG_OPTEE_REVISION_MINOR ?= 11

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

# This config variable determines the number of entries read in from RPMB at
# once whenever a function traverses the RPMB FS. Increasing the default value
# has the following consequences:
# - More memory required on heap. A single FAT entry currently has a size of
#   256 bytes.
# - Potentially significant speed-ups for RPMB I/O. Depending on how many
#   entries a function needs to traverse, the number of time-consuming RPMB
#   read-in operations can be reduced.
# Chosing a proper value is both platform- (available memory) and use-case-
# dependent (potential number of FAT fs entries), so overwrite in platform
# config files
CFG_RPMB_FS_RD_ENTRIES ?= 8

# Enables caching of FAT FS entries when set to a value greater than zero.
# When enabled, the cache stores the first 'CFG_RPMB_FS_CACHE_ENTRIES' FAT FS
# entries. The cache is populated when FAT FS entries are initially read in.
# When traversing the FAT FS entries, we read from the cache instead of reading
# in the entries from RPMB storage. Consequently, when a FAT FS entry is
# written, the cache is updated. In scenarios where an estimate of the number
# of FAT FS entries can be made, the cache may be specifically tailored to
# store all entries. The caching can improve RPMB I/O at the cost
# of additional memory.
# Without caching, we temporarily require
# CFG_RPMB_FS_RD_ENTRIES*sizeof(struct rpmb_fat_entry) bytes of heap memory
# while traversing the FAT FS (e.g. in read_fat).
# For example 8*256 bytes = 2kB while in read_fat.
# With caching, we constantly require up to
# CFG_RPMB_FS_CACHE_ENTRIES*sizeof(struct rpmb_fat_entry) bytes of heap memory
# depending on how many elements are in the cache, and additional temporary
# CFG_RPMB_FS_RD_ENTRIES*sizeof(struct rpmb_fat_entry) bytes of heap memory
# in case the cache is too small to hold all elements when traversing.
CFG_RPMB_FS_CACHE_ENTRIES ?= 0

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

# Choosing the architecture(s) of user-mode libraries (used by TAs)
#
# Platforms may define a list of supported architectures for user-mode code
# by setting $(supported-ta-targets). Valid values are "ta_arm32", "ta_arm64",
# "ta_arm32 ta_arm64" and "ta_arm64 ta_arm32".
# $(supported-ta-targets) defaults to "ta_arm32" when the TEE core is 32-bits,
# and "ta_arm32 ta_arm64" when it is 64-bits (that is, when CFG_ARM64_core=y).
# The first entry in $(supported-ta-targets) has a special role, see
# CFG_USER_TA_TARGET_<ta-name> below.
#
# CFG_USER_TA_TARGETS may be defined to restrict $(supported-ta-targets) or
# change the order of the values.
#
# The list of TA architectures is ultimately stored in $(ta-targets).

# CFG_USER_TA_TARGET_<ta-name> (for example, CFG_USER_TA_TARGET_avb), if
# defined, selects the unique TA architecture mode for building the in-tree TA
# <ta-name>. Can be either ta_arm32 or ta_arm64.
# By default, in-tree TAs are built using the first architecture specified in
# $(ta-targets).

# Address Space Layout Randomization for user-mode Trusted Applications
#
# When this flag is enabled, the ELF loader will introduce a random offset
# when mapping the application in user space. ASLR makes the exploitation of
# memory corruption vulnerabilities more difficult.
CFG_TA_ASLR ?= y

# How much ASLR may shift the base address (in pages). The base address is
# randomly shifted by an integer number of pages comprised between these two
# values. Bigger ranges are more secure because they make the addresses harder
# to guess at the expense of using more memory for the page tables.
CFG_TA_ASLR_MIN_OFFSET_PAGES ?= 0
CFG_TA_ASLR_MAX_OFFSET_PAGES ?= 128

# Address Space Layout Randomization for TEE Core
#
# When this flag is enabled, the early init code will introduce a random
# offset when mapping TEE Core. ASLR makes the exploitation of memory
# corruption vulnerabilities more difficult.
CFG_CORE_ASLR ?= y

# Load user TAs from the REE filesystem via tee-supplicant
CFG_REE_FS_TA ?= y

# Pre-authentication of TA binaries loaded from the REE filesystem
#
# - If CFG_REE_FS_TA_BUFFERED=y: load TA binary into a temporary buffer in the
#   "Secure DDR" pool, check the signature, then process the file only if it is
#   valid.
# - If disabled: hash the binaries as they are being processed and verify the
#   signature as a last step.
CFG_REE_FS_TA_BUFFERED ?= n
$(eval $(call cfg-depends-all,CFG_REE_FS_TA_BUFFERED,CFG_REE_FS_TA))

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
#
# Another option is CFG_IN_TREE_EARLY_TAS which is used to point at
# in-tree TAs. CFG_IN_TREE_EARLY_TAS is formatted as:
# <name-of-ta>/<uuid>
# for instance avb/023f8f1a-292a-432b-8fc4-de8471358067
ifneq ($(EARLY_TA_PATHS)$(CFG_IN_TREE_EARLY_TAS),)
$(call force,CFG_EARLY_TA,y)
$(call force,CFG_EMBEDDED_TS,y)
else
CFG_EARLY_TA ?= n
endif

ifneq ($(SP_PATHS),)
$(call force,CFG_SECURE_PARTITION,y)
$(call force,CFG_EMBEDDED_TS,y)
else
CFG_SECURE_PARTITION ?= n
endif

ifeq ($(CFG_EMBEDDED_TS),y)
$(call force,CFG_ZLIB,y)
endif

# Enable paging, requires SRAM, can't be enabled by default
CFG_WITH_PAGER ?= n

# Runtime lock dependency checker: ensures that a proper locking hierarchy is
# used in the TEE core when acquiring and releasing mutexes. Any violation will
# cause a panic as soon as the invalid locking condition is detected. If
# CFG_UNWIND and CFG_LOCKDEP_RECORD_STACK are both enabled, the algorithm
# records the call stacks when locks are taken, and prints them when a
# potential deadlock is found.
# Expect a significant performance impact when enabling this.
CFG_LOCKDEP ?= n
CFG_LOCKDEP_RECORD_STACK ?= y

# BestFit algorithm in bget reduces the fragmentation of the heap when running
# with the pager enabled or lockdep
CFG_CORE_BGET_BESTFIT ?= $(call cfg-one-enabled, CFG_WITH_PAGER CFG_LOCKDEP)

# Use the pager for user TAs
CFG_PAGED_USER_TA ?= $(CFG_WITH_PAGER)

# Enable support for detected undefined behavior in C
# Uses a lot of memory, can't be enabled by default
CFG_CORE_SANITIZE_UNDEFINED ?= n

# Enable Kernel Address sanitizer, has a huge performance impact, uses a
# lot of memory and need platform specific adaptations, can't be enabled by
# default
CFG_CORE_SANITIZE_KADDRESS ?= n

# Add stack guards before/after stacks and periodically check them
CFG_WITH_STACK_CANARIES ?= y

# Use compiler instrumentation to troubleshoot stack overflows.
# When enabled, most C functions check the stack pointer against the current
# stack limits on entry and panic immediately if it is out of range.
CFG_CORE_DEBUG_CHECK_STACKS ?= n

# Use when the default stack allocations are not sufficient.
CFG_STACK_THREAD_EXTRA ?= 0
CFG_STACK_TMP_EXTRA ?= 0

# Device Tree support
#
# When CFG_DT is enabled core embeds the FDT library (libfdt) allowing
# device tree blob (DTB) parsing from the core.
#
# When CFG_DT is enabled, the TEE _start function expects to find
# the address of a DTB in register X2/R2 provided by the early boot stage
# or value 0 if boot stage provides no DTB.
#
# When CFG_EMBED_DTB is enabled, CFG_EMBED_DTB_SOURCE_FILE shall define the
# relative path of a DTS file located in core/arch/$(ARCH)/dts.
# The DTS file is compiled into a DTB file which content is embedded in a
# read-only section of the core.
ifneq ($(strip $(CFG_EMBED_DTB_SOURCE_FILE)),)
CFG_EMBED_DTB ?= y
endif
ifeq ($(CFG_EMBED_DTB),y)
$(call force,CFG_DT,y)
endif
CFG_EMBED_DTB ?= n
CFG_DT ?= n

# Maximum size of the Device Tree Blob, has to be large enough to allow
# editing of the supplied DTB.
CFG_DTB_MAX_SIZE ?= 0x10000

# Device Tree Overlay support.
# This define enables support for an OP-TEE provided DTB overlay.
# One of two modes is supported in this case:
# 1. Append OP-TEE nodes to an existing DTB overlay located at CFG_DT_ADDR or
#    passed in arg2
# 2. Generate a new DTB overlay at CFG_DT_ADDR
# A subsequent boot stage must then merge the generated overlay DTB into a main
# DTB using the standard fdt_overlay_apply() method.
CFG_EXTERNAL_DTB_OVERLAY ?= n

# Enable core self tests and related pseudo TAs
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y

# This option enables OP-TEE to respond to SMP boot request: the Rich OS
# issues this to request OP-TEE to release secondaries cores out of reset,
# with specific core number and non-secure entry address.
CFG_BOOT_SECONDARY_REQUEST ?= n

# Default heap size for Core, 64 kB
CFG_CORE_HEAP_SIZE ?= 65536

# Default size of nexus heap. 16 kB. Used only if CFG_VIRTUALIZATION
# is enabled
CFG_CORE_NEX_HEAP_SIZE ?= 16384

# TA profiling.
# When this option is enabled, OP-TEE can execute Trusted Applications
# instrumented with GCC's -pg flag and will output profiling information
# in gmon.out format to /tmp/gmon-<ta_uuid>.out (path is defined in
# tee-supplicant)
# Note: this does not work well with shared libraries at the moment for a
# couple of reasons:
# 1. The profiling code assumes a unique executable section in the TA VA space.
# 2. The code used to detect at run time if the TA is intrumented assumes that
# the TA is linked statically.
CFG_TA_GPROF_SUPPORT ?= n

# TA function tracing.
# When this option is enabled, OP-TEE can execute Trusted Applications
# instrumented with GCC's -pg flag and will output function tracing
# information in ftrace.out format to /tmp/ftrace-<ta_uuid>.out (path is
# defined in tee-supplicant)
CFG_FTRACE_SUPPORT ?= n

# How to make room when the function tracing buffer is full?
# 'shift': shift the previously stored data by the amount needed in order
#    to always keep the latest logs (slower, especially with big buffer sizes)
# 'wrap': discard the previous data and start at the beginning of the buffer
#    again (fast, but can result in a mostly empty buffer)
# 'stop': stop logging new data
CFG_FTRACE_BUF_WHEN_FULL ?= shift
$(call cfg-check-value,FTRACE_BUF_WHEN_FULL,shift stop wrap)
$(call force,_CFG_FTRACE_BUF_WHEN_FULL_$(CFG_FTRACE_BUF_WHEN_FULL),y)

# Function tracing: unit to be used when displaying durations
#  0: always display durations in microseconds
# >0: if duration is greater or equal to the specified value (in microseconds),
#     display it in milliseconds
CFG_FTRACE_US_MS ?= 10000

# Core syscall function tracing.
# When this option is enabled, OP-TEE core is instrumented with GCC's
# -pg flag and will output syscall function graph in user TA ftrace
# buffer
CFG_SYSCALL_FTRACE ?= n
$(call cfg-depends-all,CFG_SYSCALL_FTRACE,CFG_FTRACE_SUPPORT)

# Enable to compile user TA libraries with profiling (-pg).
# Depends on CFG_TA_GPROF_SUPPORT or CFG_FTRACE_SUPPORT.
CFG_ULIBS_MCOUNT ?= n
# Profiling/tracing of syscall wrapper (utee_*)
CFG_SYSCALL_WRAPPERS_MCOUNT ?= $(CFG_ULIBS_MCOUNT)

ifeq (y,$(filter y,$(CFG_ULIBS_MCOUNT) $(CFG_SYSCALL_WRAPPERS_MCOUNT)))
ifeq (,$(filter y,$(CFG_TA_GPROF_SUPPORT) $(CFG_FTRACE_SUPPORT)))
$(error Cannot instrument user libraries if user mode profiling is disabled)
endif
endif

# Build libutee, libutils, libmbedtls as shared libraries.
# - Static libraries are still generated when this is enabled, but TAs will use
# the shared libraries unless explicitly linked with the -static flag.
# - Shared libraries are made of two files: for example, libutee is
#   libutee.so and 527f1a47-b92c-4a74-95bd-72f19f4a6f74.ta. The '.so' file
#   is a totally standard shared object, and should be used to link against.
#   The '.ta' file is a signed version of the '.so' and should be installed
#   in the same way as TAs so that they can be found at runtime.
CFG_ULIBS_SHARED ?= n

ifeq (yy,$(CFG_TA_GPROF_SUPPORT)$(CFG_ULIBS_SHARED))
$(error CFG_TA_GPROF_SUPPORT and CFG_ULIBS_SHARED are currently incompatible)
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

# Enable the pseudo TA for enumeration of TEE based devices for the normal
# world OS.
CFG_DEVICE_ENUM_PTA ?= y

# Define the number of cores per cluster used in calculating core position.
# The cluster number is shifted by this value and added to the core ID,
# so its value represents log2(cores/cluster).
# Default is 2**(2) = 4 cores per cluster.
CFG_CORE_CLUSTER_SHIFT ?= 2

# Define the number of threads per core used in calculating processing
# element's position. The core number is shifted by this value and added to
# the thread ID, so its value represents log2(threads/core).
# Default is 2**(0) = 1 threads per core.
CFG_CORE_THREAD_SHIFT ?= 0

# Enable support for dynamic shared memory (shared memory anywhere in
# non-secure memory).
CFG_CORE_DYN_SHM ?= y

# Enable support for reserved shared memory (shared memory in a carved out
# memory area).
CFG_CORE_RESERVED_SHM ?= y

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

# Not used since libmpa was removed. Force the values to catch build scripts
# that would set = n.
$(call force,CFG_TA_MBEDTLS_MPI,y)
$(call force,CFG_TA_MBEDTLS,y)

# Compile the TA library mbedTLS with self test functions, the functions
# need to be called to test anything
CFG_TA_MBEDTLS_SELF_TEST ?= y

# By default use tomcrypt as the main crypto lib providing an implementation
# for the API in <crypto/crypto.h>
# CFG_CRYPTOLIB_NAME is used as libname and
# CFG_CRYPTOLIB_DIR is used as libdir when compiling the library
#
# It's also possible to configure to use mbedtls instead of tomcrypt.
# Then the variables should be assigned as "CFG_CRYPTOLIB_NAME=mbedtls" and
# "CFG_CRYPTOLIB_DIR=lib/libmbedtls" respectively.
CFG_CRYPTOLIB_NAME ?= tomcrypt
CFG_CRYPTOLIB_DIR ?= core/lib/libtomcrypt

# Enable TEE_ALG_RSASSA_PKCS1_V1_5 algorithm for signing with PKCS#1 v1.5 EMSA
# without ASN.1 around the hash.
ifeq ($(CFG_CRYPTOLIB_NAME),tomcrypt)
CFG_CRYPTO_RSASSA_NA1 ?= y
endif

# Not used since libmpa was removed. Force the value to catch build scripts
# that would set = n.
$(call force,CFG_CORE_MBEDTLS_MPI,y)

# Enable virtualization support. OP-TEE will not work without compatible
# hypervisor if this option is enabled.
CFG_VIRTUALIZATION ?= n

ifeq ($(CFG_VIRTUALIZATION),y)
$(call force,CFG_CORE_RODATA_NOEXEC,y)
$(call force,CFG_CORE_RWDATA_NOEXEC,y)

# Default number of virtual guests
CFG_VIRT_GUEST_COUNT ?= 2
endif

# Enables backwards compatible derivation of RPMB and SSK keys
CFG_CORE_HUK_SUBKEY_COMPAT ?= y

# Compress and encode conf.mk into the TEE core, and show the encoded string on
# boot (with severity TRACE_INFO).
CFG_SHOW_CONF_ON_BOOT ?= n

# Enables support for passing a TPM Event Log stored in secure memory
# to a TA, so a TPM Service could use it to extend any measurement
# taken before the service was up and running.
CFG_CORE_TPM_EVENT_LOG ?= n

# When enabled, CFG_SCMI_MSG_DRIVERS embeds SCMI message drivers in the core.
# Refer to the supported SCMI features embedded upon CFG_SCMI_MSG_*
# CFG_SCMI_MSG_CLOCK embeds SCMI clock protocol support.
# CFG_SCMI_MSG_RESET_DOMAIN embeds SCMI reset domain protocol support.
# CFG_SCMI_MSG_SMT embeds SMT based message buffer of communication channel
CFG_SCMI_MSG_DRIVERS ?= n
CFG_SCMI_MSG_CLOCK ?= n
CFG_SCMI_MSG_RESET_DOMAIN ?= n
CFG_SCMI_MSG_SMT ?= n

ifneq ($(CFG_STMM_PATH),)
$(call force,CFG_WITH_STMM_SP,y)
else
CFG_WITH_STMM_SP ?= n
endif
ifeq ($(CFG_WITH_STMM_SP),y)
$(call force,CFG_ZLIB,y)
endif

# When enabled checks that buffers passed to the GP Internal Core API
# comply with the rules added as annotations as part of the definition of
# the API. For example preventing buffers in non-secure shared memory when
# not allowed.
CFG_TA_STRICT_ANNOTATION_CHECKS ?= y

# When enabled accepts the DES key sizes excluding parity bits as in
# the GP Internal API Specification v1.0
CFG_COMPAT_GP10_DES ?= y

# Defines a limit for many levels TAs may call each others.
CFG_CORE_MAX_SYSCALL_RECURSION ?= 4
