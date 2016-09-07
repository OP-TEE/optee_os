## OP-TEE with authentication framework in ARM-TF
This document gives a brief description on how to enable the verification of OP-TEE using the authentication framework in ARM-TF

---
## What we should do
* According to [user-guide.md](https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/user-guide.md), there is no additional specific build options for the verification of OP-TEE. If we have enabled the authentication framework and specified the BL32 build option when building ARM-TF, the BL32 related certificates will be created automatically by the cert_create tool, and then these certificates will be verified during booting up.


* To enable the authentication framework, the following steps should be followed according to [user-guide.md](https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/user-guide.md). All the details for these build options are also in [user-guide.md](https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/user-guide.md), more details about the authentication framework, please see [auth-framework.md](https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/auth-framework.md) and [trusted-board-boot.md](https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/trusted-board-boot.md).

   * Check out a recent version of the [mbed TLS Repository](https://github.com/ARMmbed/mbedtls.git), and then switch to tag mbedtls-2.2.0
   * Besides the normal build options, add the following build options for ARM-TF
        *  **MBEDTLS_DIR**=*path of the directory containing mbed TLS sources*
        *  **TRUSTED_BOARD_BOOT**=*1*
        *  **GENERATE_COT**=*1*
        *  **ARM_ROTPK_LOCATION**=*devel_rsa*
        *  **ROT_KEY**=*$(ARM_TF_PATH)/plat/arm/board/common/rotpk/arm_rotprivk_rsa.pem*


* Above steps have been tested on FVP platform, all verification steps are ok and xtest can run successfully without regression.
