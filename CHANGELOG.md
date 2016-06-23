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


## Issues resolved since last release
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


## Issues resolved since last release
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
