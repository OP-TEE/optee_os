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

