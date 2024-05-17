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
ifeq ($(ARCH),arm)
CROSS_COMPILE ?= arm-linux-gnueabihf-
CROSS_COMPILE64 ?= aarch64-linux-gnu-
endif
ifeq ($(ARCH),riscv)
CROSS_COMPILE ?= riscv-linux-gnu-
CROSS_COMPILE64 ?= riscv64-linux-gnu-
endif
CROSS_COMPILE32 ?= $(CROSS_COMPILE)
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
ifeq ($(DEBUG),1)
# For backwards compatibility
$(call force,CFG_CC_OPT_LEVEL,0)
$(call force,CFG_DEBUG_INFO,y)
endif

# CFG_CC_OPT_LEVEL sets compiler optimization level passed with -O directive.
# Optimize for size by default, usually gives good performance too.
CFG_CC_OPT_LEVEL ?= s

# Enabling CFG_DEBUG_INFO makes debug information embedded in core.
CFG_DEBUG_INFO ?= y

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
# 2: error + info
# 3: error + info + debug
# 4: error + info + debug + flow
CFG_TEE_CORE_LOG_LEVEL ?= 2

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

# Number of threads
CFG_NUM_THREADS ?= 2

# API implementation version
CFG_TEE_API_VERSION ?= GPD-1.1-dev

# Implementation description (implementation-dependent)
CFG_TEE_IMPL_DESCR ?= OPTEE

# Should OPTEE_SMC_CALL_GET_OS_REVISION return a build identifier to Normal
# World?
CFG_OS_REV_REPORTS_GIT_SHA1 ?= y

# The following values are not extracted from the "git describe" output because
# we might be outside of a Git environment, or the tree may have been cloned
# with limited depth not including any tag, so there is really no guarantee
# that TEE_IMPL_VERSION contains the major and minor revision numbers.
CFG_OPTEE_REVISION_MAJOR ?= 4
CFG_OPTEE_REVISION_MINOR ?= 2
CFG_OPTEE_REVISION_EXTRA ?=

# Trusted OS implementation version
TEE_IMPL_VERSION ?= $(shell git describe --always --dirty=-dev 2>/dev/null || \
		      echo Unknown_$(CFG_OPTEE_REVISION_MAJOR).$(CFG_OPTEE_REVISION_MINOR))$(CFG_OPTEE_REVISION_EXTRA)

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

# Enable roll-back protection of REE file system using RPMB.
# Roll-back protection only works if CFG_RPMB_FS = y.
CFG_REE_FS_INTEGRITY_RPMB ?= $(CFG_RPMB_FS)
$(eval $(call cfg-depends-all,CFG_REE_FS_INTEGRITY_RPMB,CFG_RPMB_FS))

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

# Print RPMB data frames sent to and received from the RPMB device
CFG_RPMB_FS_DEBUG_DATA ?= n

# Clear RPMB content at cold boot
CFG_RPMB_RESET_FAT ?= n

# Use a hard coded RPMB key instead of deriving it from the platform HUK
CFG_RPMB_TESTKEY ?= n

# Enables RPMB key programming by the TEE, in case the RPMB partition has not
# been configured yet.
# !!! Security warning !!!
# Do *NOT* enable this in product builds, as doing so would allow the TEE to
# leak the RPMB key.
# This option is useful in the following situations:
# - Testing
# - RPMB key provisioning in a controlled environment (factory setup)
CFG_RPMB_WRITE_KEY ?= n

_CFG_WITH_SECURE_STORAGE := $(call cfg-one-enabled,CFG_REE_FS CFG_RPMB_FS)

# Signing key for OP-TEE TA's
# When performing external HSM signing for TA's TA_SIGN_KEY can be set to dummy
# key and then set TA_PUBLIC_KEY to match public key from the HSM.
# TA_PUBLIC_KEY's public key will be embedded into OP-TEE OS.
TA_SIGN_KEY ?= keys/default_ta.pem
TA_PUBLIC_KEY ?= $(TA_SIGN_KEY)

# Subkeys is a complement to the normal TA_SIGN_KEY where a subkey is used
# to verify a TA instead. To sign a TA using a previously prepared subkey
# two new options are added, TA_SUBKEY_ARGS and TA_SUBKEY_DEPS.  It is
# typically used by assigning the following in the TA Makefile:
# BINARY = <TA-uuid-string>
# TA_SIGN_KEY = subkey.pem
# TA_SUBKEY_ARGS = --subkey subkey.bin --name subkey_ta
# TA_SUBKEY_DEPS = subkey.bin
# See the documentation for more details on subkeys.

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

# Build user TAs included in this source tree
CFG_BUILD_IN_TREE_TA ?= y

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

# Stack Protection for TEE Core
# This flag enables the compiler stack protection mechanisms -fstack-protector.
# It will check the stack canary value before returning from a function to
# prevent buffer overflow attacks. Stack protector canary logic will be added
# for vulnerable functions that contain:
# - A character array larger than 8 bytes.
# - An 8-bit integer array larger than 8 bytes.
# - A call to alloca() with either a variable size or a constant size bigger
#   than 8 bytes.
CFG_CORE_STACK_PROTECTOR ?= n
# This enable stack protector flag -fstack-protector-strong. Stack protector
# canary logic will be added for vulnerable functions that contain:
# - An array of any size and type.
# - A call to alloca().
# - A local variable that has its address taken.
CFG_CORE_STACK_PROTECTOR_STRONG ?= y
# This enable stack protector flag -fstack-protector-all. Stack protector canary
# logic will be added to all functions regardless of their vulnerability.
CFG_CORE_STACK_PROTECTOR_ALL ?= n
# Stack Protection for TA
CFG_TA_STACK_PROTECTOR ?= n
CFG_TA_STACK_PROTECTOR_STRONG ?= y
CFG_TA_STACK_PROTECTOR_ALL ?= n

_CFG_CORE_STACK_PROTECTOR := $(call cfg-one-enabled, CFG_CORE_STACK_PROTECTOR \
						     CFG_CORE_STACK_PROTECTOR_STRONG \
						     CFG_CORE_STACK_PROTECTOR_ALL)
_CFG_TA_STACK_PROTECTOR := $(call cfg-one-enabled, CFG_TA_STACK_PROTECTOR \
						   CFG_TA_STACK_PROTECTOR_STRONG \
						   CFG_TA_STACK_PROTECTOR_ALL)

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

# When CFG_REE_FS=y:
# Allow secure storage in the REE FS to be entirely deleted without causing
# anti-rollback errors. That is, rm /data/tee/dirf.db or rm -rf /data/tee (or
# whatever path is configured in tee-supplicant as CFG_TEE_FS_PARENT_PATH)
# can be used to reset the secure storage to a clean, empty state.
# Intended to be used for testing only since it weakens storage security.
# Warning: If enabled for release build then it will break rollback protection
# of TAs and the entire REE FS secure storage.
CFG_REE_FS_ALLOW_RESET ?= n

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
else
CFG_EARLY_TA ?= n
endif

ifeq ($(CFG_EARLY_TA),y)
$(call force,CFG_EMBEDDED_TS,y)
endif

ifneq ($(SP_PATHS),)
$(call force,CFG_EMBEDDED_TS,y)
else
CFG_SECURE_PARTITION ?= n
endif

ifeq ($(CFG_SECURE_PARTITION),y)
$(call force,CFG_EMBEDDED_TS,y)
endif

ifeq ($(CFG_EMBEDDED_TS),y)
$(call force,CFG_ZLIB,y)
endif

# By default the early TAs are compressed in the TEE binary, it is possible to
# not compress them with CFG_EARLY_TA_COMPRESS=n
CFG_EARLY_TA_COMPRESS ?= y

# Enable paging, requires SRAM, can't be enabled by default
CFG_WITH_PAGER ?= n

# Use the pager for user TAs
CFG_PAGED_USER_TA ?= $(CFG_WITH_PAGER)

# If paging of user TAs, that is, R/W paging default to enable paging of
# TAG and IV in order to reduce heap usage.
CFG_CORE_PAGE_TAG_AND_IV ?= $(CFG_PAGED_USER_TA)

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

# Enable support for detected undefined behavior in C
# Uses a lot of memory, can't be enabled by default
CFG_CORE_SANITIZE_UNDEFINED ?= n

# Enable Kernel Address sanitizer, has a huge performance impact, uses a
# lot of memory and need platform specific adaptations, can't be enabled by
# default
CFG_CORE_SANITIZE_KADDRESS ?= n

ifeq (y-y,$(CFG_CORE_SANITIZE_KADDRESS)-$(CFG_CORE_ASLR))
$(error CFG_CORE_SANITIZE_KADDRESS and CFG_CORE_ASLR are not compatible)
endif

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
# When CFG_EXTERNAL_DT is enabled, the external device tree ABI is implemented
# and the external device tree is expected to be used/modified. Its value
# defaults to CFG_DT.
#
# When CFG_MAP_EXT_DT_SECURE is enabled the external device tree is expected to
# be in the secure memory.
#
# When CFG_EMBED_DTB is enabled, CFG_EMBED_DTB_SOURCE_FILE shall define the
# relative path of a DTS file located in core/arch/$(ARCH)/dts.
# The DTS file is compiled into a DTB file which content is embedded in a
# read-only section of the core.
ifneq ($(strip $(CFG_EMBED_DTB_SOURCE_FILE)),)
CFG_EMBED_DTB ?= y
endif
ifeq ($(filter y,$(CFG_EMBED_DTB) $(CFG_CORE_SEL1_SPMC) $(CFG_CORE_SEL2_SPMC) \
		 $(CFG_CORE_EL3_SPMC)),y)
$(call force,CFG_DT,y)
endif
CFG_EMBED_DTB ?= n
CFG_DT ?= n
CFG_EXTERNAL_DT ?= $(CFG_DT)
CFG_MAP_EXT_DT_SECURE ?= n
ifeq ($(CFG_MAP_EXT_DT_SECURE),y)
$(call force,CFG_DT,y)
endif

# This option enables OP-TEE to support boot arguments handover via Transfer
# List defined in Firmware Handoff specification.
# Note: This is an experimental feature and incompatible ABI changes can be
# expected. It should be off by default until Firmware Handoff specification
# has a stable release.
# This feature requires the support of Device Tree.
CFG_TRANSFER_LIST ?= n
ifeq ($(CFG_TRANSFER_LIST),y)
$(call force,CFG_DT,y)
$(call force,CFG_EXTERNAL_DT,y)
$(call force,CFG_MAP_EXT_DT_SECURE,y)
endif

# Maximum size of the Device Tree Blob, has to be large enough to allow
# editing of the supplied DTB.
CFG_DTB_MAX_SIZE ?= 0x10000

# Maximum size of the init info data passed to Secure Partitions.
CFG_SP_INIT_INFO_MAX_SIZE ?= 0x1000

# Device Tree Overlay support.
# CFG_EXTERNAL_DTB_OVERLAY allows to append a DTB overlay into an existing
# external DTB. The overlay is created when no valid DTB overlay is found.
# CFG_GENERATE_DTB_OVERLAY allows to create a DTB overlay at external
# DTB location.
# External DTB location (physical address) is provided either by boot
# argument arg2 or from CFG_DT_ADDR if defined.
# A subsequent boot stage can then merge the generated overlay DTB into a main
# DTB using the standard fdt_overlay_apply() method.
CFG_EXTERNAL_DTB_OVERLAY ?= n
CFG_GENERATE_DTB_OVERLAY ?= n

ifeq (y-y,$(CFG_EXTERNAL_DTB_OVERLAY)-$(CFG_GENERATE_DTB_OVERLAY))
$(error CFG_EXTERNAL_DTB_OVERLAY and CFG_GENERATE_DTB_OVERLAY are exclusive)
endif
_CFG_USE_DTB_OVERLAY := $(call cfg-one-enabled,CFG_EXTERNAL_DTB_OVERLAY \
			  CFG_GENERATE_DTB_OVERLAY)

# All embedded tests are supposed to be disabled by default, this flag
# is used to control the default value of all other embedded tests
CFG_ENABLE_EMBEDDED_TESTS ?= n

# Enable core self tests and related pseudo TAs
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= $(CFG_ENABLE_EMBEDDED_TESTS)

# Compiles bget_main_test() to be called from a test TA
CFG_TA_BGET_TEST ?= $(CFG_ENABLE_EMBEDDED_TESTS)

# CFG_DT_DRIVER_EMBEDDED_TEST when enabled embedded DT driver probing tests.
# This also requires embedding a DTB with expected content.
# Default disable CFG_DRIVERS_CLK_EARLY_PROBE to probe clocks as other drivers.
# A probe deferral test mandates CFG_DRIVERS_DT_RECURSIVE_PROBE=n.
CFG_DT_DRIVER_EMBEDDED_TEST ?= n
ifeq ($(CFG_DT_DRIVER_EMBEDDED_TEST),y)
CFG_DRIVERS_CLK ?= y
CFG_DRIVERS_GPIO ?= y
CFG_DRIVERS_RSTCTRL ?= y
CFG_DRIVERS_CLK_EARLY_PROBE ?= n
$(call force,CFG_DRIVERS_DT_RECURSIVE_PROBE,n,Mandated by CFG_DT_DRIVER_EMBEDDED_TEST)
endif

# CFG_WITH_STATS when enabled embeds PTA statistics service to allow non-secure
# clients to retrieve debug and statistics information on core and loaded TAs.
CFG_WITH_STATS ?= n

# CFG_DRIVERS_DT_RECURSIVE_PROBE when enabled forces a recursive subnode
# parsing in the embedded DTB for driver probing. The alternative is
# an exploration based on compatible drivers found. It is default disabled.
CFG_DRIVERS_DT_RECURSIVE_PROBE ?= n

# This option enables OP-TEE to respond to SMP boot request: the Rich OS
# issues this to request OP-TEE to release secondaries cores out of reset,
# with specific core number and non-secure entry address.
CFG_BOOT_SECONDARY_REQUEST ?= n

# Default heap size for Core, 64 kB
CFG_CORE_HEAP_SIZE ?= 65536

# Default size of nexus heap. 16 kB. Used only if CFG_NS_VIRTUALIZATION
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
# information for all functions compiled with -pg to
# /tmp/ftrace-<ta_uuid>.out (path is defined in tee-supplicant).
CFG_FTRACE_SUPPORT ?= n

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

ifeq (y-y,$(CFG_TA_GPROF_SUPPORT)-$(CFG_ULIBS_SHARED))
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
# GlobalPlatform TEE Internal Core API (for example, re-seeding RNG entropy
# pool etc...)
CFG_SYSTEM_PTA ?= $(CFG_WITH_USER_TA)
$(eval $(call cfg-depends-all,CFG_SYSTEM_PTA,CFG_WITH_USER_TA))

# Enable the pseudo TA for enumeration of TEE based devices for the normal
# world OS.
CFG_DEVICE_ENUM_PTA ?= y

# The attestation pseudo TA provides an interface to request measurements of
# a TA or the TEE binary.
CFG_ATTESTATION_PTA ?= n
$(eval $(call cfg-depends-all,CFG_ATTESTATION_PTA,_CFG_WITH_SECURE_STORAGE))

# RSA key size (in bits) for the attestation PTA. Must be at least 528 given
# other algorithm parameters (RSA PSS with SHA-256 and 32-byte salt), but
# note that such a low value is not secure.
# See https://tools.ietf.org/html/rfc8017#section-8.1.1 and
# https://tools.ietf.org/html/rfc8017#section-9.1.1
#  emLen >= hlen + sLen + 2 = 32 + 32 + 2 = 66
#  emLen = ceil((modBits - 1) / 8) => emLen is the key size in bytes
CFG_ATTESTATION_PTA_KEY_SIZE ?= 3072

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

# Not used since libmpa was removed. Force the value to catch build scripts
# that would set = n.
$(call force,CFG_CORE_MBEDTLS_MPI,y)

# When enabled, CFG_NS_VIRTUALIZATION embeds support for virtualization in
# the non-secure world. OP-TEE will not work without a compatible hypervisor
# in the non-secure world if this option is enabled.
#
# CFG_VIRTUALIZATION served the same purpose as CFG_NS_VIRTUALIZATION but is
# deprecated as the configuration switch name was ambiguous regarding which
# world has virtualization enabled.
ifneq (undefined,$(flavor CFG_VIRTUALIZATION))
$(info WARNING: CFG_VIRTUALIZATION is deprecated, use CFG_NS_VIRTUALIZATION instead)
CFG_NS_VIRTUALIZATION ?= $(CFG_VIRTUALIZATION)
ifneq ($(CFG_NS_VIRTUALIZATION),$(CFG_VIRTUALIZATION))
$(error Inconsistent CFG_NS_VIRTUALIZATION=$(CFG_NS_VIRTUALIZATION) and CFG_VIRTUALIZATION=$(CFG_VIRTUALIZATION))
endif
endif # CFG_VIRTUALIZATION defined
CFG_NS_VIRTUALIZATION ?= n

ifeq ($(CFG_NS_VIRTUALIZATION),y)
$(call force,CFG_CORE_RODATA_NOEXEC,y)
$(call force,CFG_CORE_RWDATA_NOEXEC,y)

# Default number of virtual guests
CFG_VIRT_GUEST_COUNT ?= 2
endif

# Enables backwards compatible derivation of RPMB and SSK keys
CFG_CORE_HUK_SUBKEY_COMPAT ?= y

# Use SoC specific tee_otp_get_die_id() implementation for SSK key generation.
# This option depends on CFG_CORE_HUK_SUBKEY_COMPAT=y.
CFG_CORE_HUK_SUBKEY_COMPAT_USE_OTP_DIE_ID ?= n

# Compress and encode conf.mk into the TEE core, and show the encoded string on
# boot (with severity TRACE_INFO).
CFG_SHOW_CONF_ON_BOOT ?= n

# Enables support for passing a TPM Event Log stored in secure memory
# to a TA or FF-A SP, so a TPM Service could use it to extend any measurement
# taken before the service was up and running.
CFG_CORE_TPM_EVENT_LOG ?= n

# When enabled, CFG_SCMI_MSG_DRIVERS embeds SCMI message drivers in the core.
# Refer to the supported SCMI features embedded upon CFG_SCMI_MSG_*
#
# CFG_SCMI_MSG_CLOCK embeds SCMI clock protocol support.
# CFG_SCMI_MSG_RESET_DOMAIN embeds SCMI reset domain protocol support.
# CFG_SCMI_MSG_SMT embeds a SMT header in shared device memory buffers
# CFG_SCMI_MSG_VOLTAGE_DOMAIN embeds SCMI voltage domain protocol support.
# CFG_SCMI_MSG_SMT_FASTCALL_ENTRY embeds fastcall SMC entry with SMT memory
# CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY embeds interrupt entry with SMT memory
# CFG_SCMI_MSG_SMT_THREAD_ENTRY embeds threaded entry with SMT memory
# CFG_SCMI_MSG_SHM_MSG embeds a MSG header in cached shared memory buffer
CFG_SCMI_MSG_DRIVERS ?= n
ifeq ($(CFG_SCMI_MSG_DRIVERS),y)
CFG_SCMI_MSG_CLOCK ?= n
CFG_SCMI_MSG_RESET_DOMAIN ?= n
CFG_SCMI_MSG_SHM_MSG ?= n
CFG_SCMI_MSG_SMT ?= n
CFG_SCMI_MSG_SMT_FASTCALL_ENTRY ?= n
CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY ?= n
CFG_SCMI_MSG_SMT_THREAD_ENTRY ?= n
CFG_SCMI_MSG_THREAD_ENTRY ?= n
CFG_SCMI_MSG_VOLTAGE_DOMAIN ?= n
$(eval $(call cfg-depends-all,CFG_SCMI_MSG_SMT_FASTCALL_ENTRY,CFG_SCMI_MSG_SMT))
$(eval $(call cfg-depends-all,CFG_SCMI_MSG_SMT_INTERRUPT_ENTRY,CFG_SCMI_MSG_SMT))
$(eval $(call cfg-depends-one,CFG_SCMI_MSG_SMT_THREAD_ENTRY,CFG_SCMI_MSG_SMT CFG_SCMI_MSG_SHM_MSG))
ifeq ($(CFG_SCMI_MSG_SMT),y)
_CFG_SCMI_PTA_SMT_HEADER := y
endif
ifeq ($(CFG_SCMI_MSG_SHM_MSG),y)
_CFG_SCMI_PTA_MSG_HEADER := y
endif
endif

# CFG_SCMI_SCPFW, when enabled, embeds the reference SCMI server implementation
# from SCP-firmware package as an built-in SCMI stack in core. This
# configuration mandates target product identifier is configured with
# CFG_SCMI_SCPFW_PRODUCT and the SCP-firmware source tree path with
# CFG_SCP_FIRMWARE.
CFG_SCMI_SCPFW ?= n

ifeq ($(CFG_SCMI_SCPFW),y)
$(call force,CFG_SCMI_PTA,y,Required by CFG_SCMI_SCPFW)
ifeq (,$(CFG_SCMI_SCPFW_PRODUCT))
$(error CFG_SCMI_SCPFW=y requires CFG_SCMI_SCPFW_PRODUCT configuration)
endif
ifeq (,$(wildcard $(CFG_SCP_FIRMWARE)/CMakeLists.txt))
$(error CFG_SCMI_SCPFW=y requires CFG_SCP_FIRMWARE configuration)
endif
endif #CFG_SCMI_SCPFW

ifeq ($(CFG_SCMI_MSG_DRIVERS)-$(CFG_SCMI_SCPFW),y-y)
$(error CFG_SCMI_MSG_DRIVERS=y and CFG_SCMI_SCPFW=y are mutually exclusive)
endif

# When enabled, CFG_SCMI_MSG_USE_CLK embeds SCMI clocks registering services for
# the platform SCMI server and implements the platform plat_scmi_clock_*()
# functions.
CFG_SCMI_MSG_USE_CLK ?= n
$(eval $(call cfg-depends-all,CFG_SCMI_MSG_USE_CLK,CFG_DRIVERS_CLK CFG_SCMI_MSG_DRIVERS))

# Enable SCMI PTA interface for REE SCMI agents
CFG_SCMI_PTA ?= n
ifeq ($(CFG_SCMI_PTA),y)
_CFG_SCMI_PTA_SMT_HEADER ?= n
_CFG_SCMI_PTA_MSG_HEADER ?= n
endif

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

# Pseudo-TA to export hardware RNG output to Normal World
# RNG characteristics are platform specific
CFG_HWRNG_PTA ?= n
ifeq ($(CFG_HWRNG_PTA),y)
# Output rate of hw_get_random_bytes() in bytes per second, 0: not rate-limited
CFG_HWRNG_RATE ?= 0
# Quality/entropy of hw_get_random_bytes() per 1024 bits of output data, in bits
ifeq (,$(CFG_HWRNG_QUALITY))
$(error CFG_HWRNG_QUALITY not defined)
endif
endif

# CFG_PREALLOC_RPC_CACHE, when enabled, makes core to preallocate
# shared memory for each secure thread. When disabled, RPC shared
# memory is released once the secure thread has completed is execution.
ifeq ($(CFG_WITH_PAGER),y)
CFG_PREALLOC_RPC_CACHE ?= n
endif
CFG_PREALLOC_RPC_CACHE ?= y

# When enabled, CFG_DRIVERS_CLK embeds a clock framework in OP-TEE core.
# This clock framework allows to describe clock tree and provides functions to
# get and configure the clocks.
# CFG_DRIVERS_CLK_DT embeds devicetree clock parsing support
# CFG_DRIVERS_CLK_FIXED add support for "fixed-clock" compatible clocks
# CFG_DRIVERS_CLK_EARLY_PROBE makes clocks probed at early_init initcall level.
# CFG_DRIVERS_CLK_PRINT_TREE embeds a helper function to print the clock tree
# state on OP-TEE core console with the debug trace level.
CFG_DRIVERS_CLK ?= n
CFG_DRIVERS_CLK_DT ?= $(call cfg-all-enabled,CFG_DRIVERS_CLK CFG_DT)
CFG_DRIVERS_CLK_FIXED ?= $(CFG_DRIVERS_CLK_DT)
CFG_DRIVERS_CLK_EARLY_PROBE ?= $(CFG_DRIVERS_CLK_DT)
CFG_DRIVERS_CLK_PRINT_TREE ?= n

$(eval $(call cfg-depends-all,CFG_DRIVERS_CLK_DT,CFG_DRIVERS_CLK CFG_DT))
$(eval $(call cfg-depends-all,CFG_DRIVERS_CLK_FIXED,CFG_DRIVERS_CLK_DT))

# When enabled, CFG_DRIVERS_RSTCTRL embeds a reset controller framework in
# OP-TEE core to provide reset controls on subsystems of the devices.
CFG_DRIVERS_RSTCTRL ?= n

# When enabled, CFG_DRIVERS_GPIO embeds a GPIO controller framework in
# OP-TEE core to provide GPIO support for drivers.
CFG_DRIVERS_GPIO ?= n

# When enabled, CFG_DRIVERS_I2C provides I2C controller and devices support.
CFG_DRIVERS_I2C ?= n

# When enabled, CFG_DRIVERS_NVMEM provides a framework to register nvmem
# providers and allow consumer drivers to get NVMEM cells using the Device Tree.
CFG_DRIVERS_NVMEM ?= n

# When enabled, CFG_DRIVERS_PINCTRL embeds a pin muxing controller framework in
# OP-TEE core to provide drivers a way to apply pin muxing configurations based
# on device-tree.
CFG_DRIVERS_PINCTRL ?= n

# When enabled, CFG_DRIVERS_REGULATOR embeds a voltage regulator framework in
# OP-TEE core to provide drivers a common regulator interface and describe
# the regulators dependencies using an embedded device tree.
#
# When enabled, CFG_REGULATOR_FIXED embeds a voltage regulator driver for
# DT compatible "regulator-fixed" devices.
#
# When enabled, CFG_REGULATOR_GPIO embeds a voltage regulator driver for
# DT compatible "regulator-gpio" devices.
#
# CFG_DRIVERS_REGULATOR_PRINT_TREE embeds a helper function to print the
# regulator tree state on OP-TEE core console with the info trace level.
CFG_DRIVERS_REGULATOR ?= n
CFG_DRIVERS_REGULATOR_PRINT_TREE ?= n
CFG_REGULATOR_FIXED ?= n
CFG_REGULATOR_GPIO ?= n

$(eval $(call cfg-enable-all-depends,CFG_REGULATOR_FIXED, \
	 CFG_DRIVERS_REGULATOR CFG_DT))
$(eval $(call cfg-enable-all-depends,CFG_REGULATOR_GPIO, \
	 CFG_DRIVERS_REGULATOR CFG_DT CFG_DRIVERS_GPIO))

# When enabled, CFG_INSECURE permits insecure configuration of OP-TEE core
# and shows a print (info level) when booting up the device that
# indicates that the board runs a standard developer configuration.
#
# A developer configuration doesn't necessarily have to be secure. The intention
# is that the one making products based on OP-TEE should override this flag in
# plat-xxx/conf.mk for the platform they're basing their products on after
# they've finalized implementing stubbed functionality (see OP-TEE
# documentation/Porting guidelines) as well as vendor specific security
# configuration.
#
# CFG_WARN_INSECURE served the same purpose as CFG_INSECURE but is deprecated.
ifneq (undefined,$(flavor CFG_WARN_INSECURE))
$(info WARNING: CFG_WARN_INSECURE is deprecated, use CFG_INSECURE instead)
CFG_INSECURE ?= $(CFG_WARN_INSECURE)
ifneq ($(CFG_INSECURE),$(CFG_WARN_INSECURE))
$(error Inconsistent CFG_INSECURE=$(CFG_INSECURE) and CFG_WARN_INSECURE=$(CFG_WARN_INSECURE))
endif
endif # CFG_WARN_INSECURE defined
CFG_INSECURE ?= y

# Enables warnings for declarations mixed with statements
CFG_WARN_DECL_AFTER_STATEMENT ?= y

# Branch Target Identification (part of the ARMv8.5 Extensions) provides a
# mechanism to limit the set of locations to which computed branch instructions
# such as BR or BLR can jump. To make use of BTI in TEE core and ldelf on CPU's
# that support it, enable this option. A GCC toolchain built with
# --enable-standard-branch-protection is needed to use this option.
CFG_CORE_BTI ?= n

$(eval $(call cfg-depends-all,CFG_CORE_BTI,CFG_ARM64_core))

# To make use of BTI in user space libraries and TA's on CPU's that support it,
# enable this option.
CFG_TA_BTI ?= $(CFG_CORE_BTI)

$(eval $(call cfg-depends-all,CFG_TA_BTI,CFG_ARM64_core))

ifeq (y-y,$(CFG_NS_VIRTUALIZATION)-$(call cfg-one-enabled, CFG_TA_BTI CFG_CORE_BTI))
$(error CFG_NS_VIRTUALIZATION and BTI are currently incompatible)
endif

ifeq (y-y,$(CFG_PAGED_USER_TA)-$(CFG_TA_BTI))
$(error CFG_PAGED_USER_TA and CFG_TA_BTI are currently incompatible)
endif

# Memory Tagging Extension (part of the ARMv8.5 Extensions) implements lock
# and key access to memory. This is a hardware supported alternative to
# CFG_CORE_SANITIZE_KADDRESS which covers both S-EL1 and S-EL0.
CFG_MEMTAG ?= n

$(eval $(call cfg-depends-all,CFG_MEMTAG,CFG_ARM64_core))
ifeq (y-y,$(CFG_CORE_SANITIZE_KADDRESS)-$(CFG_MEMTAG))
$(error CFG_CORE_SANITIZE_KADDRESS and CFG_MEMTAG are not compatible)
endif
ifeq (y-y,$(CFG_WITH_PAGER)-$(CFG_MEMTAG))
$(error CFG_WITH_PAGER and CFG_MEMTAG are not compatible)
endif

# Privileged Access Never (PAN, part of the ARMv8.1 Extensions) can be
# used to restrict accesses to unprivileged memory from privileged mode.
# For RISC-V architecture, CSR {m|s}status.SUM bit is used to implement PAN.
CFG_PAN ?= n

$(eval $(call cfg-depends-one,CFG_PAN,CFG_ARM64_core CFG_RV64_core CFG_RV32_core))

ifeq ($(filter y, $(CFG_CORE_SEL1_SPMC) $(CFG_CORE_SEL2_SPMC) \
		  $(CFG_CORE_EL3_SPMC)),y)
# FF-A case, handled via the FF-A ABI
CFG_CORE_ASYNC_NOTIF ?= y
$(call force,_CFG_CORE_ASYNC_NOTIF_DEFAULT_IMPL,n)
else
# CFG_CORE_ASYNC_NOTIF is defined by the platform to enable support
# for sending asynchronous notifications to normal world.
# Interrupt ID must be configurged by the platform too. Currently is only
# CFG_CORE_ASYNC_NOTIF_GIC_INTID defined.
CFG_CORE_ASYNC_NOTIF ?= n
$(call force,_CFG_CORE_ASYNC_NOTIF_DEFAULT_IMPL,$(CFG_CORE_ASYNC_NOTIF))
endif

# Enable callout service
CFG_CALLOUT ?= $(CFG_CORE_ASYNC_NOTIF)

# Enable notification based test watchdog
CFG_NOTIF_TEST_WD ?= $(CFG_ENABLE_EMBEDDED_TESTS)
$(eval $(call cfg-depends-all,CFG_NOTIF_TEST_WD,CFG_CALLOUT \
	 CFG_CORE_ASYNC_NOTIF))

$(eval $(call cfg-enable-all-depends,CFG_MEMPOOL_REPORT_LAST_OFFSET, \
	 CFG_WITH_STATS))

# Pointer Authentication (part of ARMv8.3 Extensions) provides instructions
# for signing and authenticating pointers against secret keys. These can
# be used to mitigate ROP (Return oriented programming) attacks. This is
# currently done by instructing the compiler to add paciasp/autiasp at the
# begging and end of functions to sign and verify ELR.
#
# The CFG_CORE_PAUTH enables these instructions for the core parts
# executing at EL1, with one secret key per thread and one secret key per
# physical CPU.
#
# The CFG_TA_PAUTH option enables these instructions for TA's at EL0. When
# this option is enabled, TEE core will initialize secret keys per TA.
CFG_CORE_PAUTH ?= n
CFG_TA_PAUTH ?= $(CFG_CORE_PAUTH)

$(eval $(call cfg-depends-all,CFG_CORE_PAUTH,CFG_ARM64_core))
$(eval $(call cfg-depends-all,CFG_TA_PAUTH,CFG_ARM64_core))

ifeq (y-y,$(CFG_NS_VIRTUALIZATION)-$(CFG_CORE_PAUTH))
$(error CFG_NS_VIRTUALIZATION and CFG_CORE_PAUTH are currently incompatible)
endif
ifeq (y-y,$(CFG_NS_VIRTUALIZATION)-$(CFG_TA_PAUTH))
$(error CFG_NS_VIRTUALIZATION and CFG_TA_PAUTH are currently incompatible)
endif

ifeq (y-y,$(CFG_TA_GPROF_SUPPORT)-$(CFG_TA_PAUTH))
$(error CFG_TA_GPROF_SUPPORT and CFG_TA_PAUTH are currently incompatible)
endif

ifeq (y-y,$(CFG_FTRACE_SUPPORT)-$(CFG_TA_PAUTH))
$(error CFG_FTRACE_SUPPORT and CFG_TA_PAUTH are currently incompatible)
endif

# Enable support for generic watchdog registration
# This watchdog will then be usable by non-secure world through SMC calls.
CFG_WDT ?= n

# Enable watchdog SMC handling compatible with arm-smc-wdt Linux driver
CFG_WDT_SM_HANDLER ?= n

$(eval $(call cfg-enable-all-depends,CFG_WDT_SM_HANDLER,CFG_WDT))

# When CFG_WDT_SM_HANDLER=y, SMC function ID 0x82003D06 default implements
# arm-smc-wdt service. Platform can also override this ID with a platform
# specific SMC function ID to access arm-smc-wdt service thanks to
# optional config switch CFG_WDT_SM_HANDLER_ID.
CFG_WDT_SM_HANDLER_ID ?= 0x82003D06

# Allow using the udelay/mdelay function for platforms without ARM generic timer
# extension. When set to 'n', the plat_get_freq() function must be defined by
# the platform code
CFG_CORE_HAS_GENERIC_TIMER ?= y

# Enable RTC API
CFG_DRIVERS_RTC ?= n

# Enable PTA for RTC access from non-secure world
CFG_RTC_PTA ?= n

# Enable the FF-A SPMC tests in xtests
CFG_SPMC_TESTS ?= n

# Allocate the translation tables needed to map the S-EL0 application
# loaded
CFG_CORE_PREALLOC_EL0_TBLS ?= n
ifeq (y-y,$(CFG_CORE_PREALLOC_EL0_TBLS)-$(CFG_WITH_PAGER))
$(error "CFG_WITH_PAGER can't support CFG_CORE_PREALLOC_EL0_TBLS")
endif

# User TA runtime context dump.
# When this option is enabled, OP-TEE provides a debug method for
# developer to dump user TA's runtime context, including TA's heap stats.
# Developer can open a stats PTA session and then invoke command
# STATS_CMD_TA_STATS to get the context of loaded TAs.
CFG_TA_STATS ?= n

# Enables best effort mitigations against fault injected when the hardware
# is tampered with. Details in lib/libutils/ext/include/fault_mitigation.h
CFG_FAULT_MITIGATION ?= y

# Enables TEE Internal Core API v1.1 compatibility for in-tree TAs. Note
# that this doesn't affect libutee itself, it's only the TAs compiled with
# this set that are affected. Each out-of-tree must set this if to enable
# compatibility with version v1.1 as the value of this variable is not
# preserved in the TA dev-kit.
CFG_TA_OPTEE_CORE_API_COMPAT_1_1 ?= n

# Change supported HMAC key size range, from 64 to 1024.
# This is needed to pass AOSP Keymaster VTS tests:
#   Link to tests : https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/3.0/vts/functional/keymaster_hidl_hal_test.cpp
#   Module: VtsHalKeymasterV3_0TargetTest
#   Testcases: - PerInstance/SigningOperationsTest#
#              - PerInstance/NewKeyGenerationTest#
#              - PerInstance/ImportKeyTest#
#              - PerInstance/EncryptionOperationsTest#
#              - PerInstance/AttestationTest#
# Note that this violates GP requirements of HMAC size range.
CFG_HMAC_64_1024_RANGE ?= n

# CFG_RSA_PUB_EXPONENT_3, when enabled, allows RSA public exponents in the
# range 3 <= e < 2^256. This is needed to pass AOSP KeyMint VTS tests:
#    Link to tests: https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
#    Module: VtsAidlKeyMintTargetTest
#    Testcases: - PerInstance/EncryptionOperationsTest.RsaNoPaddingSuccess
# When CFG_RSA_PUB_EXPONENT_3 is disabled, RSA public exponents must conform
# to NIST SP800-56B recommendation and be in the range 65537 <= e < 2^256.
CFG_RSA_PUB_EXPONENT_3 ?= n

# Enable a hardware pbkdf2 function
# By default use standard pbkdf2 implementation
CFG_CRYPTO_HW_PBKDF2 ?= n
$(eval $(call cfg-depends-all,CFG_CRYPTO_HW_PBKDF2,CFG_CRYPTO_PBKDF2))

# CFG_HALT_CORES_ON_PANIC, when enabled, makes any call to panic() halt the
# other cores. The feature currently relies on GIC device to trap the other
# cores using an SGI interrupt specified by CFG_HALT_CORES_ON_PANIC_SGI.
CFG_HALT_CORES_ON_PANIC ?= n
CFG_HALT_CORES_ON_PANIC_SGI ?= 15
$(eval $(call cfg-depends-all,CFG_HALT_CORES_ON_PANIC,CFG_GIC))

# Enable automatic discovery of maximal PA supported by the hardware and
# use that. Provides easier configuration of virtual platforms where the
# maximal PA can vary.
CFG_AUTO_MAX_PA_BITS ?= n

# CFG_DRIVERS_REMOTEPROC, when enabled, embeds support for remote processor
# management including generic DT bindings for the configuration.
CFG_DRIVERS_REMOTEPROC ?= n

# CFG_REMOTEPROC_PTA, when enabled, embeds remote processor management PTA
# service.
CFG_REMOTEPROC_PTA ?= n

# When enabled, CFG_WIDEVINE_HUK uses the widevine HUK provided by secure
# DTB as OP-TEE HUK.
CFG_WIDEVINE_HUK ?= n
$(eval $(call cfg-depends-all,CFG_WIDEVINE_HUK,CFG_DT))

# When enabled, CFG_WIDEVINE_PTA embeds a PTA that exposes the keys under
# DT node "/options/op-tee/widevine" to some specific TAs.
CFG_WIDEVINE_PTA ?= n
$(eval $(call cfg-depends-all,CFG_WIDEVINE_PTA,CFG_DT CFG_WIDEVINE_HUK))

# CFG_SEMIHOSTING_CONSOLE, when enabled, embeds a semihosting console driver.
# When CFG_SEMIHOSTING_CONSOLE_FILE=NULL, OP-TEE console reads/writes
# trace messages from/to the debug terminal of the semihosting host computer.
# When CFG_SEMIHOSTING_CONSOLE_FILE="{your_log_file}", OP-TEE console
# outputs trace messages to that file. Output to "optee.log" by default.
CFG_SEMIHOSTING_CONSOLE ?= n
ifeq ($(CFG_SEMIHOSTING_CONSOLE),y)
$(call force,CFG_SEMIHOSTING,y)
endif
CFG_SEMIHOSTING_CONSOLE_FILE ?= "optee.log"
ifeq ($(CFG_SEMIHOSTING_CONSOLE_FILE),)
$(error CFG_SEMIHOSTING_CONSOLE_FILE cannot be empty)
endif

# Semihosting is a debugging mechanism that enables code running on an embedded
# system (also called the target) to communicate with and use the I/O of the
# host computer.
CFG_SEMIHOSTING ?= n

# CFG_FFA_CONSOLE, when enabled, embeds a FFA console driver. OP-TEE console
# writes trace messages via FFA interface to the SPM (Secure Partition Manager)
# like hafnium.
CFG_FFA_CONSOLE ?= n
