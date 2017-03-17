# OP-TEE - version 2.4.0

[Link][github_commits_2_4_0] to a list of all commits between this release and
the previous one (2.3.0).

Please note: this release is API-compatible with the previous one, but the
Secure Storage internal format for the REE and SQL FS is not compatible due to
commits [a238b74][commit_a238b74] ("core: REE FS: use the new hash tree
interface") and [44e900e][commit_44e900e] ("core: SQL FS: use the new hash tree
interface").

## New features

* Add porting guidelines

* Add support for Secure Data Path which allows Client and Trusted Applications
  to share references to secure memory

* New supported platform: Texas Instruments AM57xx (`PLATFORM=ti-am57xx`)

* ARMv7-A: add support for platform services in secure monitor and add these
  services for the DRA7xx platform

* SPI framework and PL022 driver cleanup and improvements

* Use CNTPCT (when available) to add entropy to the software PRNG

* Add GlobalPlatform Socket API for UDP and TCP (IPv4 and IPv6)

* DRA7: add TRNG driver, enable GICv2 driver

* Support load address larger than 4G

* libutee: preserve error code when calling TEE_Panic() for easier
  troubleshooting

* Support TA profiling with gprof (-pg compiler switch)

* Optimize the ELF loader for TAs when pager is enabled

* Update documentation

* Add paged secure shared memory that can be transferred between TAs as
  needed

* Introduce MOBJ abstraction

* i.MX6: add PSCI "on" function

* arm32: introduce PSCI framework

## Bug fixes

* Secure storage: improve integrity checking of the REE and SQL filesystems by
  adding a hash tree on the internal data structures. Any external modification
  is detected, except full rollback. Fixes [#1188][issue1188].

* The linux driver will set the 'privileged' flag (TEE_GEN_CAP_PRIVILEGED) on
  the device intended for use by tee-supplicant. Fixes [#1199][issue1199].

* RPMB: don't try to program the RPMB key by default

* Fix "make clean" error cases

* Fix issue when resetting persistent storage enumerator [#1332][issue1332]

* Fix TA panic when doing AES CTS with specific buffer sizes
  [#1203][issue1203].

## Known issues

* On RPi3 xtest sometimes stall (rcu_sched self-detected stall on CPU) [#1353][issue1353]
* For multi-core PSCI support is to be added for ls1021atwr in OP-TEE.
* USB keyboard cannot be used to stop the u-boot timeout ([build issue131]).
* Travis service (build.git) seems unstable from time to time.

## Tested on

In the list below, _standard_ means that the `xtest` program passed with
its default configuration, while _extended_ means it was run successfully
with the additional GlobalPlatform™ TEE Initial Configuration Test Suite
v1.1.0.4.

If a platform is not listed, it means the release was not tested on this
platform.

<!-- ${PLATFORM}-${PLATFORM_FLAVOR}, ordered alphabetically -->
* d02: extended
* hikey: extended
* imx-mx6ulevk: standard
* ls-ls1021atwr: standard (single core)
* mediatek-mt8173: standard
* rcar-h3: standard
* rpi3: standard
* stm-b2260: extended
* ti-dra7xx: standard
* vexpress-fvp: standard
* vexpress-juno: standard
* vexpress-qemu_armv8a: standard
* vexpress-qemu_virt: standard
* zynqmp-zc1751_dc1: standard
* zynqmp-zc1751_dc2: standard
* zynqmp-zcu102: standard

[github_commits_2_4_0]: https://github.com/OP-TEE/optee_os/compare/2.3.0...2.4.0
[issue1332]: https://github.com/OP-TEE/optee_os/issues/1332
[issue1353]: https://github.com/OP-TEE/optee_os/issues/1353
[build issue131]: https://github.com/OP-TEE/build/issues/131
[commit_a238b74]: https://github.com/OP-TEE/optee_os/commit/a238b744b1b3
[commit_44e900e]: https://github.com/OP-TEE/optee_os/commit/44e900eabfc1

# OP-TEE - version 2.3.0

[Link][github_commits_2_3_0] to a list of all commits between this release and
the previous one (2.2.0).

Please note: this release is API-compatible with the previous one, but the
Secure Storage internal format for the REE FS is not compatible due to commit
[361fb3e][commit_361fb3e] ("core: REE FS: use a single file per object").

[commit_361fb3e]: https://github.com/OP-TEE/optee_os/commit/361fb3e

## New features

* New supported platform: Xilinx Zynq 7000 ZC702 (`PLATFORM=zynq7k-zc702`)

* Add debug assertions to spinlocks and mutexes

* Add more CP15 register access macros for Cortex-A9

* ARMv7-A: redesign secure monitor to make it easier to register services

* ARMv7-A: cleanup boot arguments

* libutee: extend `TEE_CheckMemoryAccessRights()` with
  `TEE_MEMORY_ACCESS_SECURE` and `TEE_MEMORY_ACCESS_NONSECURE`

* plat-hikey: enable SPI by default and add sample test code

* Consider `CFLAGS_ta_arm64` and `CFLAGS_ta_arm32` when building TAs

* Secure storage refactoring
  - Simplify interface with tee-supplicant. Minimize round trips with normal
    world, especially by adding a cache for FS RPC payload data.
  - REE FS: use a single file per object, remove block cache.

* Print call stack in panic()

## Bug fixes

* Fix UUID encoding when communicating with normal world (use big endian
  mode instead of native endianness). Related to this, the string format
  for UUIDs has changed in tee-supplicant, so that TA file names now follow
  the format defined in RFC4122 (a missing hyphen was added). The old format
  is still supported, but deprecated, and will likely be removed with the
  next major release.

* Drop write permission to non-writable ELF segments after TA loading is
  complete.

* mm: fix confusing memory mapping debug traces

* plat-ti: fix issues with MMU mapping

* crypto: fix clearing of big numbers

* build: allow spaces and double quotes in CFG_ variables

* mm: use paddr_t to support both 32- and 64-bit architectures properly.
  Resolves 32-bit truncation error when pool is at top of 32 bit address
  space on 64-bit architecture.

* plat-stm: support pager. Fix pager on ARMv7-A SMP boards.

* Fix debug output of Trusted Applications (remove "ERROR: TEE-CORE:" prefix)

* Do not consider TA memref parameters as TA private memory

* crypto: fix `cipher_final()` which would not call `cbc_done()` for CBC_MAC
  algorithms

* fix for 16-way PL310

* arm32: fix call stack unwinding (`print_stack()`)

* arm32: fix spinlock assembly code

* plat-stm, plat-imx: fix SCR initalization

* Fix user L1 MMU entries calculation (non-LPAE), allowing TTBCR.N values
  other than 7.

* mtk-mt8173: fix panic caused by incorrect size of SHMEM

* plat-stm: fix RNG driver (non-flat mapping)

## Known issues

* New issues open on GitHub
  * [#1203][issue1203] AES-CTS mode will fail when inlen=0x100, in_incr=0x80
  * [#1199][issue1199] Both tee and teepriv reported GlobalPlatform compliant
  * [#1188][issue1188] Secure storage (SQL FS and REE FS): blocks not tied to
    current meta header
  * [#1172][issue1172] paddr_t should be larger than 32 bits when
    CFG_WITH_LPAE is enabled

## Tested on

In the list below, _standard_ means that the `xtest` program passed with
its default configuration, while _extended_ means it was run successfully
with the additional GlobalPlatform™ TEE Initial Configuration Test Suite
v1.1.0.4.

If a platform is not listed, it means the release was not tested on this
platform.

<!-- ${PLATFORM}-${PLATFORM_FLAVOR}, ordered alphabetically -->
* d02: extended
* hikey: extended
* imx-mx6ulevk: standard
* ls-ls1021atwr: standard
* mediatek-mt8173: standard
* rcar-h3: standard
* rpi3: standard
* stm-b2260: extended
* stm-cannes: extended
* ti-dra7xx: standard
* vexpress-fvp: standard
* vexpress-juno: standard
* vexpress-qemu_armv8a: standard
* vexpress-qemu_virt: extended
* zynqmp-zcu102: standard

[github_commits_2_3_0]: https://github.com/OP-TEE/optee_os/compare/2.2.0...2.3.0
[issue1172]: https://github.com/OP-TEE/optee_os/issues/1172
[issue1188]: https://github.com/OP-TEE/optee_os/issues/1188
[issue1199]: https://github.com/OP-TEE/optee_os/issues/1199
[issue1203]: https://github.com/OP-TEE/optee_os/issues/1203

# OP-TEE - version 2.2.0

[Link][github_commits_2_2_0] to a list of all commits between this release and
the previous one (2.1.0).

Please note: this release is API-compatible with the previous one, but the
Secure Storage internal format is not compatible due to commit
[fde4a75][commit_fde4a75] ("storage: encrypt the FEK with a TA-specific key").

[commit_fde4a75]: https://github.com/OP-TEE/optee_os/commit/fde4a75

## New features

* New supported platforms:
	* Freescale i.MX6 Quad SABRE Lite & SD
	* HiSilicon D02
	* Raspberry Pi3
	* Renesas RCAR H3
	* STMicroelectronics b2260 - h410

* Pager: Support paging of read/write pages by encrypting them with AES-GCM.
  Support paging of user TAs. Add global setting for TZSRAM size
  (CFG_CORE_TZSRAM_EMUL_SIZE), defaults to 300K.

* Support for more than 8 CPU cores

* Added SPI framework and PL022 driver

* GPIO: framework supports multiple instances, PL061 driver now has get/set
  interrupt and mode control functions

* Secure storage: Encrypt the File Encryption Key with a TA-specific key for
  better TA isolation. Add build-time and run-time support for multiple storage
  backends. Add SQLite backend.

* Trusted User Interface: some code is introduced to support the implementation
  of TUI. This includes: a generic framebuffer driver, display and serial
  abstractions, and drivers for PL111 (LCD) / PL050 (KMI) / TZC400 and PS2
  mouse.

* AES acceleration using ARMv8-A Cryptographic Extensions instructions is
  now supported in AArch32 mode

* Add support for GCC flags: -fsanitize=undefined and -fsanitize=kernel-address

* Use a global setting for core heap size (CFG_CORE_HEAP_SIZE), 64K by default.

* Add macros to unwind and print the call stack of TEE core

* Libtomcrypt: sync with the latest `develop` branch.

* The Trusted Application SDK (ta_dev_kit.mk) can produce libraries (.a)

* Rework assertions and TEE core panics and properly honor NDEBUG

## Bug fixes

* Fix incorrect algorithm passed to cipher.final()

* scripts: support Python 2.x and 3.x

* Secure storage: Add proper locking to support concurrent access. Fix sign
  extension bug with offset parameter of syscall storage_obj_seek which could
  cause errors in Aarch32 mode. Fix reading beyond end of file.

* Aarch64: mask all maskable exceptions before doing a normal return from call.

* Device Tree: add no-map property to OP-TEE node in reserved-memory.

* LibTomcrypt: fix CVE-2016-6129

## Known issues

* New issues open on GitHub
  * [#1093][issue1093] rcar-h3: xtest 6010 hangs
  * [#1092][issue1092] rcar-h3: xtest 4010 fails
  * [#1081][issue1081] Bad mapping of TA secure memref parameters
  * [#1071][issue1071] __data_end may not correctly represent text start position when using CFG_WITH_PAGER
  * [#1069][issue1069] armv7/Aarch32: crash in stack unwind (DPRINT_STACK())

## Tested on

In the list below, _standard_ means that the `xtest` program passed with
its default configuration, while _extended_ means it was run successfully
with the additional GlobalPlatform™ TEE Initial Configuration Test Suite
v1.1.0.4.

If a platform is not listed, it means the release was not tested on this
platform.

<!-- ${PLATFORM}-${PLATFORM_FLAVOR}, ordered alphabetically -->
* d02: extended
* hikey: extended
* imx-mx6qsabrelite: standard
* imx-mx6qsabresd: standard
* rcar-h3: standard, pass except issues [#1092][issue1092] and [#1093][issue1093]
* rpi3: standard
* stm-b2260: standard
* stm-cannes: standard
* ti-dra7xx: standard
* vexpress-fvp: standard
* vexpress-juno: standard
* vexpress-qemu_armv8a: standard
* vexpress-qemu_virt: extended
* zynqmp-zcu102: standard

[github_commits_2_2_0]: https://github.com/OP-TEE/optee_os/compare/2.1.0...2.2.0
[issue1081]: https://github.com/OP-TEE/optee_os/issues/1081
[issue1071]: https://github.com/OP-TEE/optee_os/issues/1071
[issue1069]: https://github.com/OP-TEE/optee_os/issues/1069
[issue1092]: https://github.com/OP-TEE/optee_os/issues/1092
[issue1093]: https://github.com/OP-TEE/optee_os/issues/1093

# OP-TEE - version 2.1.0

## New features

* New supported platforms:
	* Xilinx Zynq UltraScale+ MPSOC
	* Spreadtrum SC9860

* GCC5 support

* Non Linear Mapping support: In OP-TEE kernel mode, the physical to virtual
  addresses was linear until this release, meaning the virtual addresses
  were equal to the physical addresses. This is no more the case in this
  release.

* Font rendering routines have been introduced in order to ease an
  implementation of Trusted UI.

* File Storage: Possibility to use the normal world filesystem and the RPMB
  implementations simultaneously.

* AOSP: There is a [local manifest][aosp_local_manifest] to build OP-TEE into an AOSP build, running on HiKey.
  Please refer to the README in that repo for instructions.

* OpenEmbedded: In addition to the makefile-based build described in the optee_os README, there is an
  [OpenEmbedded-based build][oe_build] that supports Qemu (32-bit), FVP (64-bit), and HiKey (64-bit).
  Please refer to the README in that repo for instructions.

* [Link][github_commits_2_1_0] to a list of all commits between this and
  previous release.


## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The [optee_test][optee_test] project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |

*	ARM Juno Board (vexpress-juno), standard.
*	Foundation Models (vexpress-fvp), standard tests + extended tests,
	using FVP ARM V8 Foundation Platformr0p0 (platform build 10.0.37)
*	FSL i.MX6 UltraLite EVK (imx), standard.
*	FSL ls1021a (ls-ls1021atwr), standard tests.
*	HiKey (hikey), standard + extended tests.
*	QEMU (vexpress-qemu), standard + extended tests.
*	Xilinx Zynq UltraScale+ MPSOC, standard tests

Note that the following platform has not been tested:
*	MTK8173-EVB (mediatek-mt8173)


## Known issues
* Issue(s) open on GitHub
  * [#868][pr868]: python-wand font generation sometimes times out
  * [#863][pr863]: "double free or corruption" error when building optee_os
  * [#858][pr858]: UUIDs in binary format have wrong endinanness
  * [#857][pr857]: Formatting of UUIDs is incorrect
  * [#847][pr847]: optee_os panic(TEE-CORE: Assertion)
  * [#838][pr838]: TUI font rendering is _very_ slow
  * [#814][pr814]: Persistent objects : save informations after close
  * [#665][pr665]: xtest 1013 stalled on HiKey when log levels are 4 and optee_os is on its own UART
  * [#506][pr506]: tee-supplicant panic & ta panic

[github_commits_2_1_0]: https://github.com/OP-TEE/optee_os/compare/2.0.0...2.1.0
[pr868]: https://github.com/OP-TEE/optee_os/issues/868
[pr863]: https://github.com/OP-TEE/optee_os/issues/863
[pr858]: https://github.com/OP-TEE/optee_os/issues/858
[pr857]: https://github.com/OP-TEE/optee_os/issues/857
[pr847]: https://github.com/OP-TEE/optee_os/issues/847
[pr838]: https://github.com/OP-TEE/optee_os/issues/838
[pr814]: https://github.com/OP-TEE/optee_os/issues/814
[pr665]: https://github.com/OP-TEE/optee_os/issues/665
[aosp_local_manifest]: https://github.com/linaro-swg/optee_android_manifest
[oe_build]: https://github.com/linaro-swg/oe-optee

# OP-TEE - version 2.0.0

## New features

* Generic driver: A new generic TEE driver is in the process of being
  [upstreamed][gendrv_v9].
  In this release, [OP-TEE/optee_linuxdriver][optee_linuxdriver] is no more used.
  Instead, linux v4.5 is being patched using the proposed Generic TEE Driver,
  as it can be found in [https://github.com/linaro-swg/linux/tree/optee][linux_optee]

* RPMB support: Secure Storage can now use Replay Protected Memory Block (RPMB) partition
  of an eMMC device. Check the [full documentation][rpmb_doc]

* Hard-float ABI is now available.

* [Link][github_commits_2_0_0] to a list of all commits between this and
  previous release.


## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The [optee_test][optee_test] project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |

*	ARM Juno Board (vexpress-juno), standard.
*	Foundation Models (vexpress-fvp), standard tests + extended tests,
	using FVP ARM V8 Foundation Platformr0p0 (platform build 9.5.40)
*	FSL ls1021a (ls-ls1021atwr), standard.
*	HiKey (hikey), standard.
*	MTK8173-EVB (mediatek-mt8173), standard.
*	QEMU (vexpress-qemu), standard + extended tests.
*	STM Cannes (stm-cannes), standard + extended tests.

## Known issues
* Issue(s) open on GitHub
  * [#40][prld40] BUG_ON() when re-using RPC buffer to tee-supplicant
  * [#506][pr506]: tee-supplicant panic & ta panic

[github_commits_2_0_0]: https://github.com/OP-TEE/optee_os/compare/1.1.0...2.0.0
[rpmb_doc]: https://github.com/OP-TEE/optee_os/blob/master/documentation/secure_storage_rpmb.md
[optee_linuxdriver]: https://github.com/OP-TEE/optee_linuxdriver
[gendrv_v9]: https://lkml.org/lkml/2016/4/1/205
[linux_optee]: https://github.com/linaro-swg/linux/tree/optee


# OP-TEE - version 1.1.0


## New features

* Softfloat library: floating point support is now available in 32bits TA.

* Support running 64-bits TA: on ARMv8-A platform, TA can be compiled in
  AArch32 and/or in AArch64 in case the core is compiled in AArch64.
  An example can be found in HiKey configuration file. Using the following
  excerpt code, the user TA libraries are compiled in both AArch32 and
  AArch64, and can be found in `out/arm-plat-hikey/export-ta_arm32` and
  `out/arm-plat-hikey/export-ta_arm64`

```
    ta-targets = ta_arm32
    ta-targets += ta_arm64
```

* Concurrent TA support: multiple TA can run in parallel on
  several cores.

* New tests added in xtest test suite: concurrent TA (xtest 1013),
  floating point tests (xtest 1006 and os_test TA) and corruption
  file storage (xtest 20000)

* [Link][github_commits_1_1_0] to a list of all commits between this and
  previous release.


## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The [optee_test][optee_test] project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |
| Hello world test | Plain hello world Trusted Application such as [this][hello_world]. |

*	Foundation Models (vexpress-fvp), standard tests + extended tests,
	using FVP ARM V8 Foundation Platformr0p0 (platform build 9.5.40)
*	HiKey (hikey), standard + extended tests.
*	MT8173 (mediatek), standard tests.
*	QEMU (vexpress-qemu), standard + extended tests.
*	STM Cannes (stm-cannes), standard + extended tests.

## Known issues
* Secure Storage is implemented, but note that anti-rollback protection
  is not implemented yet.

* Issue(s) open on GitHub
  * [#40][prld40] BUG_ON() when re-using RPC buffer to tee-supplicant
  * [#296][pr296]: Connecting RPMB to the storage APIs.
  * [#493][pr493]: setup_juno_optee: unable to find pre-built binaries
  * [#506][pr506]: tee-supplicant panic & ta panic

[prld40]: https://github.com/OP-TEE/optee_linuxdriver/issues/40
[pr506]: https://github.com/OP-TEE/optee_os/issues/506
[github_commits_1_1_0]: https://github.com/OP-TEE/optee_os/compare/1.0.1...1.1.0



# OP-TEE - version 1.0.0

OP-TEE is now maintained by Linaro. Contributors do not need to
sign a CLA anymore, but must follow the rules of the [DCO][DCO]
(Developer Certificate of Origin) instead.


## New features

* Add hardware support for Texas Instruments DRA7xx, ARMv7 (plat-ti)

* GlobalPlatform™ TEE Internal Core API Specification v1.1,
  including ECC algorithms.

* Secure Storage: Files stored by the REE are now encrypted. Operations
  are made atomic in order to prevent inconsistencies in case of errors
  during the storage operations. [Slides][LCStorage] describing the
  Secure Storage have been presented at the Linaro Connect SFO15.

* Change of format of the Trusted Applications: they follow a
  [signed ELF format][elf]

* Rework thread [synchronization][synchro] in optee_os.

* Use of ARMv8 native cryptographic support.

* [OP-TEE/optee_test][optee_test] test suite is released.

* Introduce [OP-TEE/manifest][manifest] and [OP-TEE/build][build]
  to setup and build QEMU, FVP, HiKey and Mediatek platforms. Setup scripts
  that used to be in optee_os have been removed, except for Juno board.

* [Link][github_commits_1_0_0] to a list of all commits between this and
  previous release.


## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The [optee_test][optee_test] project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |
| Hello world test | Plain hello world Trusted Application such as [this][hello_world]. |

*	ARM Juno Board (vexpress-juno), standard + extended tests.
*	Foundation Models (vexpress-fvp), standard tests.
*	HiKey (hikey), standard + extended tests.
*	MT8173 (mediatek), standard tests.
*	QEMU (vexpress-qemu), standard + extended tests.
*	STM Cannes (stm-cannes), standard + extended tests.

## Known issues
* Secure Storage is implemented, but note that anti-rollback protection
  is not implemented yet.

* Issue(s) open on GitHub
  * [#210][pr210]: libteec.so 32-bit does not communicate well
    with 64-bit kernel module
  * [#296][pr296]: Connecting RPMB to the storage APIs.
  * [#493][pr493]: setup_juno_optee: unable to find pre-built binaries
  * [#494][pr494]: HiKey: xtest 7671 fails (1.0.0-rc2)

[pr210]: https://github.com/OP-TEE/optee_os/issues/210
[pr296]: https://github.com/OP-TEE/optee_os/issues/296
[pr493]: https://github.com/OP-TEE/optee_os/issues/493
[pr494]: https://github.com/OP-TEE/optee_os/issues/494
[github_commits_1_0_0]: https://github.com/OP-TEE/optee_os/compare/0.3.0...1.0.0
[DCO]: https://github.com/OP-TEE/optee_os/blob/master/Notice.md#contributions
[LCStorage]: http://www.slideshare.net/linaroorg/sfo15503-secure-storage-in-optee
[synchro]: https://github.com/OP-TEE/optee_os/blob/master/documentation/optee_design.md#4-thread-handling
[elf]: https://github.com/OP-TEE/optee_os/blob/master/documentation/optee_design.md#format
[optee_test]: https://github.com/OP-TEE/optee_test
[manifest]: https://github.com/OP-TEE/manifest
[build]: https://github.com/OP-TEE/build



# OP-TEE - version 0.3.0

## New features

*   Add hardware support for
	*   Mediatek MT8173 Board, ARMv8-A (plat-mediatek)
	*   Hisilicon HiKey Board, ARMv8-A (plat-hikey)
*   AArch64 build of optee_os is now possible through the configuration `CFG_ARM64_core=y`
*	Secure Storage: Data can be encrypted prior to their storage in the non-secure.
	Build is configured using `CFG_ENC_FS=y`
*	A generic boot scheme can be used. Boot configuration is commonalized. This helps
	new board support. It is applied on plat-hikey, plat-vexpress, plat-mediatek, plat-stm
    and plat-vexpress.

## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The optee_test project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |
| Hello world test | Plain hello world Trusted Application such as [this][hello_world]. |

*	ARM Juno Board (vexpress-juno), standard tests.
*	Foundation Models (vexpress-fvp), standard tests.
*	HiKey (hikey), standard tests.
*	MT8173 (mediatek), standard tests.
*	QEMU (vexpress-qemu), standard + extended tests.
*	STM Cannes (stm-cannes), standard + extended tests.

-------------------------------------------

# OP-TEE - version 0.2.0

## New features

### Linux Driver Refactoring

Linux Driver has been refactored. It is now split in two parts:
*	optee.ko, the generic Linux driver. It contains all functionality
	common to all backends.
*	optee_armtz.ko, a specific backend dedicated to the TrustZone optee.
	It depends on optee.ko.

Loading the TrustZone optee linux driver module is now performed using

    modprobe optee_armtz

Thanks to the dependency between the generic and the backend modules, optee.ko is then automatically loaded.

### Misc new features
* support PL310 lock down at TEE boot
* add 64bits support (division / print)

## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The optee_test project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.1.0.4. |
| Hello world test | Plain hello world Trusted Application such as [this][hello_world]. |

*   ARM Juno Board (vexpress-juno), standard tests + extended tests.

*   Foundation Models (vexpress-fvp), standard + extended tests.

*   QEMU (vexpress-qemu), standard + extended tests.

*   STM Cannes (stm-cannes), standard + extended tests.


## Issues resolved since last release
*	Fix user TA trace issue, in order each TA is able to select its own trace level


-------------------------------------------
#OP-TEE - version 0.1.0

## New features
Below is a summary of the most important features added, but at the end you will
find a link that present you all commits between the current and previous
release tag.

*   GlobalPlatform Client API v1.0 support.

*   GlobalPlatform Internal API v1.0 support.

*   GlobalPlatform Secure Elements v1.0 support.

*   Add hardware support for

    *   Allwinner A80, ARMv7-A.

    *   ARM Juno Board, ARMv8-A.

    *   Foundation Models, ARMv8-A.

    *   Fast Models, ARMv8-A.

    *   QEMU, ARMv7-A.

    *   STM Cannes, ARMv7-A.

    *   STM Orly2, ARMv7-A.

*   Add LibTomCrypt as the default software cryptographic library.

*   Add cryptographic abstraction layer in on secure side to ease the use of
    other cryptographic software libraries or adding support for hardware
    acceleration.

*   Extended cryptographic API with support for HKDF, Concat KDF and PBKDF2.

*   SHA-1 and SHA-256 ARMv8-A crypto extension implementation.

*   Enabled paging support in OP-TEE OS.

*   Add support for xtest (both standard and extended) in QEMU and FVP setup
    scripts.

*   Add documentation for the OS design, cryptographic abstraction layer, secure
    elements design, the build system, GitHub usage, key derivation extensions,
    ARM-Trusted Firmware usage within OP-TEE and GlobalPlatform usage within
    OP-TEE.

*   Integrate support for Travis CI.

*   [Link][github_commits_0_1_0] to a list of all commits between this and
    previous release.


## Tested on
Definitions:

| Type | Meaning |
| ---- | ------- |
| Standard tests | The optee_test project. |
| Extended tests | optee_test with tests from the GlobalPlatform™ TEE Initial Configuration Test Suite v1.0.0. |
| Hello world test | Plain hello world Trusted Application such as [this][hello_world]. |

*   Allwinner A80 (plat-sunxi), hello world test.

*   ARM Juno Board (vexpress-juno), standard tests.

*   Foundation Models (plat-vexpress-fvp), standard + extended tests

*   QEMU (plat-vexpress-qemu), standard + extended tests (and Secure Elements
    tested separately).

*   STM Cannes (plat-stm-cannes), standard + extended tests.


## Issues resolved since last release
N/A since this is the first release tag on OP-TEE.


## Known issues
*   Storage is implemented, but not "Secure storage", meaning that a client
    needs to do encrypt files on their own before storing the files.

*   Issue(s) open on GitHub
    *   [#95][pr95]: An error about building the test code of libtomcrypt.

    *   [#149][pr149]: when testing optee os with arm trusted firmware (I
	utilized optee os tee.bin as bl32 image) on juno platform, I got an
        error.

    *   [#161][pr161]: tee_svc_cryp.c lacks accessibility checks on
        user-supplied TEE_Attributes.

[hello_world]: https://github.com/jenswi-linaro/lcu14_optee_hello_world
[github_commits_0_1_0]: https://github.com/OP-TEE/optee_os/compare/b01047730e77127c23a36591643eeb8bb0487d68...999e4a6c0f64d3177fd3d0db234107b6fb860884
[pr95]: https://github.com/OP-TEE/optee_os/issues/95
[pr149]: https://github.com/OP-TEE/optee_os/issues/149
[pr161]: https://github.com/OP-TEE/optee_os/issues/161

*   Global Platform Device Internal Core API v1.1
    *   [#230][pr230]: Persistent object corruption support (TEE_ERROR_CORRUPT_OBJECT/_2)
    *   [#230][pr230]: Persistent object access support (TEE_ERROR_STORAGE_NOT_AVAILABLE/_2)
