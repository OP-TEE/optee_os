/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Marvell.
 */

#ifndef __EHSM_H__
#define __EHSM_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Number of mailboxes available in eHSM */
#define EHSM_NUM_MAILBOXES		2

enum ehsm_mailboxes {
	EHSM_MAILBOX0 = 0,
	EHSM_MAILBOX1 = 1,
};

#define EHSM_NUM_ARGS			16
#define EHSM_ALIGNMENT			32UL

/*
 * Encryption linked list size is 5 as we could have up to 4 entries and
 * the NULL termination entry.
 */
#define EHSM_OUTPUT_LINKED_LIST_SIZE	5

enum ehsm_regs {
	/* Request input registers */
	EHSM_INPUT_ARG0             = (0x0),
	EHSM_INPUT_ARG1             = (0x4),
	EHSM_INPUT_ARG2             = (0x8),
	EHSM_INPUT_ARG3             = (0xc),
	EHSM_INPUT_ARG4             = (0x10),
	EHSM_INPUT_ARG5             = (0x14),
	EHSM_INPUT_ARG6             = (0x18),
	EHSM_INPUT_ARG7             = (0x1c),
	EHSM_INPUT_ARG8             = (0x20),
	EHSM_INPUT_ARG9             = (0x24),
	EHSM_INPUT_ARG10            = (0x28),
	EHSM_INPUT_ARG11            = (0x2c),
	EHSM_INPUT_ARG12            = (0x30),
	EHSM_INPUT_ARG13            = (0x34),
	EHSM_INPUT_ARG14            = (0x38),
	EHSM_INPUT_ARG15            = (0x3c),
	EHSM_INPUT_CMD              = (0x40),

	/* Request output registers */
	EHSM_CMD_RET_STATUS         = (0x80),
	EHSM_CMD_RET_PARAMETER0     = (0x84),
	EHSM_CMD_RET_PARAMETER1     = (0x88),
	EHSM_CMD_RET_PARAMETER2     = (0x8c),
	EHSM_CMD_RET_PARAMETER3     = (0x90),
	EHSM_CMD_RET_PARAMETER4     = (0x94),
	EHSM_CMD_RET_PARAMETER5     = (0x98),
	EHSM_CMD_RET_PARAMETER6     = (0x9c),
	EHSM_CMD_RET_PARAMETER7     = (0xa0),
	EHSM_CMD_RET_PARAMETER8     = (0xa4),
	EHSM_CMD_RET_PARAMETER9     = (0xa8),
	EHSM_CMD_RET_PARAMETER10    = (0xac),
	EHSM_CMD_RET_PARAMETER11    = (0xb0),
	EHSM_CMD_RET_PARAMETER12    = (0xb4),
	EHSM_CMD_RET_PARAMETER13    = (0xb8),
	EHSM_CMD_RET_PARAMETER14    = (0xbc),
	EHSM_CMD_RET_PARAMETER15    = (0xc0),

	/* Status register */
#define EHSM_CMD_FIFO_STATUS_CMD_EXE_CORE_ID                BIT(16)
#define EHSM_CMD_FIFO_STATUS_READY                          BIT(8)
#define EHSM_CMD_FIFO_STATUS_CORE1_CMD_STATUS_READ_DONE     BIT(7)
#define EHSM_CMD_FIFO_STATUS_CORE0_CMD_STATUS_READ_DONE     BIT(6)
#define EHSM_CMD_FIFO_STATUS_CORE1_CMD_STATUS_BUFFER_FULL   BIT(5)
#define EHSM_CMD_FIFO_STATUS_CORE0_CMD_STATUS_BUFFER_FULL   BIT(4)
	EHSM_CMD_FIFO_STATUS        = (0xc4),

	/* Host interrupt reset register */
	EHSM_CORE0_HOST_INT_RST_REG = (0xc8),
#define EHSM_CMD_CPL_STS_BIT                    BIT(0)
	EHSM_CORE0_HOST_INT_MASK_REG        = (0xcc),

	/* Shadow register definitions */
#define EHSM_LCS_REG_VALID                      1
#define EHSM_PERMANENT_SOC_JTAG_STATE           5
#define EHSM_DIS_UART_STATE                     7
#define EHSM_DIS_SOC_JTAG_STATE                 8
#define EHSM_LCS_STATE_MASK                     0xF
#define EHSM_RAW_STATE                          0x0
#define EHSM_PROVISION_STATE                    0x1
#define EHSM_DEPLOY_STATE                       0x3
#define EHSM_FA_STATE                           0x7
#define EHSM_SHADOW_REGS_VALID_BIT              1
	EHSM_SHADOW_REG_STATUS      = (0x100),

	/* UUID registers */
	EHSM_UUID0                  = (0x104),
	EHSM_UUID1                  = (0x108),
	EHSM_UUID2                  = (0x10c),

	/* Shadow registers */
	EHSM_LCS_DEBUG_STATUS       = (0x114),
#define EHSM_DISABLE_BOOT_STRAP0                0
#define EHSM_DISABLE_BOOT_STRAP1                1
#define EHSM_DISABLE_BOOT_STRAP2                2
#define EHSM_DISABLE_BOOT_STRAP3                3
#define EHSM_DISABLE_BOOT_STRAP4                4
#define EHSM_DISABLE_BOOT_STRAP5                5
#define EHSM_DISABLE_BOOT_STRAP6                6
#define EHSM_SECURE_BOOT                        7
#define EHSM_ENCRYPTED_BOOT                     8
#define EHSM_MEASURED_BOOT                      9
#define EHSM_SECURE_BOOT_LOCK                   10
#define EHSM_ENCRYPTED_BOOT_LOCK                11
#define EHSM_MEASURED_BOOT_LOCK                 12
#define EHSM_SCHEME_ID_MASK                     0x0000F0000
#define EHSM_SCHEME_ID_SHIFT                    16
#define EHSM_SCHEME_ID(X)       (((X) << EHSM_SCHEME_ID_SHIFT) & \
						EHSM_SCHEME_ID_MASK)
#define EHSM_SCHEME_ID_SET(X, V) (((X) & ~EHSM_SCHEME_ID_MASK) | \
						EHSM_SCHEME_ID(V))
	EHSM_BOOTROM_STATUS                 = (0x118),
	EHSM_ROOT_TRUST_STATUS              = (0x11c),
#define EHSM_KEY_REV_CONTROL_SHIFT              16
#define EHSM_KEY_REV_CONTROL_MASK               0x00070000
#define EHSM_KEY_REV_CONTROL(X) (((X) << EHSM_KEY_REV_CONTROL_SHIFT) & \
						EHSM_KEY_REV_CONTROL_MASK)
	EHSM_KEY_REVOC_STATUS               = (0x120),
#define EHSM_LOADER_FW_MASK                     0x0000000F
#define EHSM_LOADER_FW(X)       ((X) & EHSM_LOADER_FW_MASK)
	EHSM_SEC_VER_REG                    = (0x124),
	EHSM_BOOTSTRAP_PIN_STATUS           = (0x128),
	EHSM_REMAINING_CONFIG_STATUS        = (0x12c),
	EHSM_CHAIN_OF_TRUST_STATUS          = (0x130),

	/* Request input registers */
	EHSM_CORE1_INPUT_ARG0               = (0x140),
	EHSM_CORE1_INPUT_ARG1               = (0x144),
	EHSM_CORE1_INPUT_ARG2               = (0x148),
	EHSM_CORE1_INPUT_ARG3               = (0x14c),
	EHSM_CORE1_INPUT_ARG4               = (0x150),
	EHSM_CORE1_INPUT_ARG5               = (0x154),
	EHSM_CORE1_INPUT_ARG6               = (0x158),
	EHSM_CORE1_INPUT_ARG7               = (0x15c),
	EHSM_CORE1_INPUT_ARG8               = (0x160),
	EHSM_CORE1_INPUT_ARG9               = (0x164),
	EHSM_CORE1_INPUT_ARG10              = (0x168),
	EHSM_CORE1_INPUT_ARG11              = (0x16c),
	EHSM_CORE1_INPUT_ARG12              = (0x170),
	EHSM_CORE1_INPUT_ARG13              = (0x174),
	EHSM_CORE1_INPUT_ARG14              = (0x178),
	EHSM_CORE1_INPUT_ARG15              = (0x17c),
	EHSM_CORE1_INPUT_CMD                = (0x180),

	/* Request output registers */
	EHSM_CORE1_CMD_RET_STATUS           = (0x1a0),
	EHSM_CORE1_CMD_RET_PARAMETER0       = (0x1a4),
	EHSM_CORE1_CMD_RET_PARAMETER1       = (0x1a8),
	EHSM_CORE1_CMD_RET_PARAMETER2       = (0x1ac),
	EHSM_CORE1_CMD_RET_PARAMETER3       = (0x1b0),
	EHSM_CORE1_CMD_RET_PARAMETER4       = (0x1b4),
	EHSM_CORE1_CMD_RET_PARAMETER5       = (0x1b8),
	EHSM_CORE1_CMD_RET_PARAMETER6       = (0x1bc),
	EHSM_CORE1_CMD_RET_PARAMETER7       = (0x1c0),
	EHSM_CORE1_CMD_RET_PARAMETER8       = (0x1c4),
	EHSM_CORE1_CMD_RET_PARAMETER9       = (0x1c8),
	EHSM_CORE1_CMD_RET_PARAMETER10      = (0x1cc),
	EHSM_CORE1_CMD_RET_PARAMETER11      = (0x1d0),
	EHSM_CORE1_CMD_RET_PARAMETER12      = (0x1d4),
	EHSM_CORE1_CMD_RET_PARAMETER13      = (0x1d8),
	EHSM_CORE1_CMD_RET_PARAMETER14      = (0x1dc),
	EHSM_CORE1_CMD_RET_PARAMETER15      = (0x1e0),

	/* Host interrupt reset register */
	EHSM_CORE1_HOST_INT_RST_REG         = (0x1e4),
	EHSM_CORE1_HOST_INT_MASK_REG        = (0x1e8),

};

enum ehsm_status {
	STATUS_SUCCESS                              = 0,

	// these status
	STATUS_APB_MISCOMPARE                       = 6,
	STATUS_APB_SLAVE_ERROR                      = 7,
	STATUS_MAILBOX_MISCOMPARE                   = 8,
	STATUS_BAD_XBAR_PATH                        = 9,
	STATUS_BAD_SP_ACCESS_MODE                   = 10,
	STATUS_BAD_CRYPT_ENGINE                     = 11,
	STATUS_BAD_AES_MODE                         = 12,
	STATUS_BAD_HASH_ALGORITHM                   = 13,
	STATUS_BAD_ZMODP_ALGORITHM                  = 14,
	STATUS_BAD_ECP_ALGORITHM                    = 15,
	STATUS_BAD_ECP_BIT_STRENGTH                 = 16,
	STATUS_OTP_CORRUPTED                        = 17,
	STATUS_SCRATCHPAD_OVERFLOW                  = 18,
	STATUS_BAD_SIGNATURE_LENGTH                 = 19,
	STATUS_SIGNATURE_LENGTH_OVERFLOW            = 20,
	STATUS_HASH_UPDATE_LENGTH_ERROR             = 21,

	// whenever possible, have the status match that of the production IROM
	STATUS_FAILURE                              = 255,
	STATUS_NO_RESOURCES                         = 257,
	STATUS_BAD_DEVICE                           = 258,
	STATUS_NULL_BUFFER                          = 259,
	STATUS_UNSUPPORTED_FUNCTION                 = 262,
	STATUS_UNSUPPORTED_PARAMETER                = 263,
	STATUS_ILLEGAL_BLOCK_SIZE                   = 267,
	STATUS_PARAMETER_OUT_OF_RANGE               = 269,
	STATUS_NULL_POINTER                         = 270,
	STATUS_OVERRUN_ERROR                        = 275,
	STATUS_OFFSET_ERROR                         = 276,
	STATUS_BAD_TRANSFER_SIZE                    = 286,
	STATUS_FATAL_INTERNAL_ERROR                 = 288,
	STATUS_INVALID_SIGNATURE                    = 292,
	STATUS_INTEGER_TOO_LARGE                    = 296,
	STATUS_DMA_TIMEOUT                          = 299,
	STATUS_DMA_BUS_ERROR                        = 300,
	STATUS_DMA_PARITY_ERROR                     = 301,
	STATUS_DMA_LINKED_LIST_ACCESS_ERROR         = 302,
	STATUS_DMA_PAUSE_COMPLETION_TIMEOUT         = 303,
	STATUS_DMA_IDIOPATHIC_ERROR                 = 304,
	STATUS_HASH_TIMEOUT                         = 305,
	STATUS_AES_TIMEOUT                          = 306,
	STATUS_ZMODP_TIMEOUT                        = 307,
	STATUS_EC_TIMEOUT                           = 308,
	STATUS_MCT_TIMEOUT                          = 312,
	STATUS_EBG_TIMEOUT                          = 313,
	STATUS_OTP_TIMEOUT                          = 314,
	STATUS_BUS_ERROR                            = 317,
	STATUS_DIGEST_MISMATCH                      = 320,
	STATUS_INSUFFICIENT_PRIVILEGE               = 321,
	STATUS_BAD_ENGINE_ID                        = 354,
	STATUS_INVALID_TOKEN                        = 359,
	STATUS_EROM_ALREADY_LOADED                  = 365,
	STATUS_BIU_MAILBOX_OVERRUN                  = 366,
	STATUS_INVALID_OTP_FIELD                    = 367,
	STATUS_PATCH_EROM_ALREADY_LOADED            = 368,
	STATUS_APB_ENGINE_ERROR                     = 369,
	STATUS_APB_TIMEOUT                          = 370,
	STATUS_MCT_OVERFLOW                         = 371,

	STATUS_ECDSA_VERIFY_FAILED                  = 512,
	STATUS_INVALID_LENGTH                       = 513,
	STATUS_INVALID_KEY_LENGTH                   = 514,
	STATUS_NULL_ENTROPY                         = 515,
	STATUS_NULL_NONCE                           = 516,
	STATUS_INVALID_ENTROPY_LENGTH               = 517,
	STATUS_INVALID_HANDLE                       = 518,
	STATUS_UNINITIALIZED_INSTANCE               = 519,
	STATUS_NULL_INTERNAL_POINTER                = 520,
	STATUS_CORRUPTED_HANDLE                     = 521,
	STATUS_INVALID_HANDLE_INDEX                 = 522,
	STATUS_INVALID_HANDLE_COUNT                 = 523,
	STATUS_INVALID_HANDLE_OFFSET                = 524,
	STATUS_INVALID_STRING_LENGTH                = 525,
	STATUS_STRING_UNDERFLOW                     = 526,
	STATUS_STRING_OVERFLOW                      = 527,
	STATUS_NULL_ENTROPY_BUFFER                  = 528,
	STATUS_REQUESTED_LENGTH_TOO_LARGE           = 529,
	STATUS_DRBG_CATASTROPHIC_ERROR              = 530,
	STATUS_DRBG_ERROR                           = 531,
	STATUS_NOT_IMPLEMENTED                      = 532,
	STATUS_INT_TIMEOUT                          = 533,
	STATUS_GHASH_TIMEOUT                        = 534,

	STATUS_AES_LENGTH_ERROR                     = 535,
	STATUS_AES_GCM_TAG_ERROR                    = 536,
	STATUS_AES_DATA_TRANSFER_ERROR              = 537,
	STATUS_ZMODP_INVALID_OPERAND                = 538,
	STATUS_ZMODP_DATA_TRANSFER_ERROR            = 539,
	STATUS_RC4_TIMEOUT                          = 540,
	STATUS_DES_TIMEOUT                          = 541,
	STATUS_RC4_DATA_TRANSFER_ERROR              = 542,
	STATUS_DES_DATA_TRANSFER_ERROR              = 543,
	STATUS_DES_LENGTH_ERROR                     = 544,
	STATUS_NULL_ECP_PRIME                       = 545,
	STATUS_ECP_INVALID_MODE                     = 546,
	STATUS_ECP_INVALID_ZERO                     = 547,
	STATUS_ECP_ZERO_OUTPUT                      = 548,
	STATUS_ECP_ZERO_INVERSE                     = 549,

	STATUS_OTP_UNCORRECTABLE_ERROR              = 550,
	STATUS_OTP_RKEK_UNAVAILABLE                 = 551,
	STATUS_AUTHENTICATION_TOKEN_MISMATCH        = 552,
	STATUS_CODE_BINDING_DIGEST_MISMATCH         = 553,
	STATUS_INVALID_PAYLOAD_COMMAND              = 554,
	STATUS_NOT_HD_EFUSE_OTP                     = 555,

	STATUS_UNKNOWN_AES_ERROR                    = 556,
	STATUS_UNKNOWN_DES_ERROR                    = 558,
	STATUS_UNKNOWN_HASH_ERROR                   = 559,
	STATUS_UNKNOWN_ZMODP_ERROR                  = 560,
	STATUS_UNKNOWN_ECP_ERROR                    = 561,
	STATUS_RSA_LENGTH_MISMATCH_ERROR            = 562,
	STATUS_INVALID_ARGUMENT                     = 563,
	STATUS_INVALID_TAG_SIZE                     = 564,
	STATUS_MNK_ECC_ERROR                        = 565,
	STATUS_INDIVIDUAL_UUID_MISMATCH             = 566,

	/* Additional OTP errors */
	STATUS_INVALID_REQUEST                      = 601,
	STATUS_INVALID_KEY                          = 602,
	STATUS_INVALID_KEY_ID                       = 603,
	STATUS_INVALID_SCHEME_ID                    = 604,
	STATUS_LIFECYCLE_POLICY_VIOLATION           = 605,
	STATUS_OTP_PROVISION_HW_FAILURE             = 606,
	STATUS_OTP_FIELD_LOCKED                     = 607,
	STATUS_OTP_FIELD_READ_DISABLED              = 608,
	STATUS_OTP_FIELD_ALREADY_PROVISIONED        = 609,
	STATUS_OTP_FIELD_NOT_PROVISIONED            = 610,
	STATUS_OTP_SHADOW_REG_MISMATCH              = 611,
	STATUS_OTP_ECC_TIMEOUT                      = 612,
	STATUS_OTP_SHADOWING_TIMEOUT                = 613,
	STATUS_OTP_ECC_UNCORRECTABLE_ERROR          = 614,
	STATUS_KEY_ID3_MISSING                      = 615,
	STATUS_OTP_ENABLE_DISABLE_EXHAUSTED         = 616,
	STATUS_OTP_UUID_NOT_PROVISIONED             = 617,
	STATUS_UNSUPPORTED_KEY_PROVISION_OPTION     = 618,

	 /* puf related errors */
	STATUS_PUF_UDS_NOT_INSTANTIATED             = 620,
	STATUS_PUF_UDS_INSTANTIATED                 = 621,
	STATUS_PUF_HW_ERROR_STATE                   = 622,
	STATUS_PUF_HW_TIMEOUT                       = 623,
	STATUS_PUF_KEY_QUALITY_CHECK_FAILURE        = 624,
	STATUS_PUF_INSTANTIATE_FAILURE              = 625,
	STATUS_PUF_KEY_GEN_FAILURE                  = 626,
	STATUS_PUF_HEALTH_TEST_FAILURE              = 627,
	STATUS_PUF_INVALIDATE_FAILURE               = 628,
	STATUS_PUF_AGING_TEST_TIMEOUT               = 629,
	STATUS_PUF_REAGENT_MISMATCH                 = 630,
	STATUS_PUF_REAGENT_UNCORRETABLE             = 631,

	/* Additional encrypted boot and measured boot errors */
	STATUS_KM_VERSION_MISMATCH                  = 640,
	STATUS_INVALID_CSK_KEY_ID                   = 641,
	STATUS_SCHEME_ID_MISMATCH                   = 642,
	STATUS_UDS_LOAD_DISABLE                     = 643,

	STATUS_KEY_MANIFEST_NOT_LOADED              = 644,
	STATUS_KEY_MANIFEST_ALREADY_LOADED          = 645,
	STATUS_KEY_MANIFEST_OVERSIZE                = 646,
	STATUS_AUTH_KEY_BIND_UNPROVISIONED          = 647,
	STATUS_CHALLENGE_MISMATCH                   = 648,
	STATUS_INVALID_TOKEN_SIZE                   = 649,
	STATUS_DMA_UNALIGNED_ADDRESS                = 650,
	STATUS_KAK_UNPROVISIONED                    = 651,
	STATUS_ZERO_TOKEN                           = 652,
	STATUS_INVALID_KC_ID                        = 653,
	/* KM = key manifest */
	STATUS_INVALID_KM_VERSION                   = 654,

	STATUS_SIDE_LOAD_KEY_FAILURE                = 655,
	STATUS_UNSUPPORTED_DIGEST_TYPE              = 656,
	STATUS_INVALID_EC_POINT                     = 657,
	STATUS_EC521_POINT_PADDDING_ERROR           = 658,
	STATUS_PIE_OVERSIZE                         = 659,
	STATUS_HEAP_OVERFLOW                        = 660,
	STATUS_INVALID_PM_STATUS                    = 661,
	STATUS_ECP_DISABLED                         = 662,
	STATUS_INVALID_CHECKSUM                     = 663,
	STATUS_INVALID_AUTH_CMD_PACKAGE             = 664,
	STATUS_KEY_MANIFEST_LOCKED                  = 665,
	STATUS_DISABLED_IN_FIPS_MODE                = 666,
	STATUS_DMA_LINKED_LIST_UNALIGNED            = 667,
	STATUS_DMA_LINKED_LIST_TRAS_OVERSIZE        = 668,

	/* new SHA3 and SHAKE exclusive errors */
	STATUS_INVALID_SHAKE_DIGEST_LENGTH          = 670,
	STATUS_HMAC_SHALL_NOT_USE_SHAKE             = 671,
	STATUS_SHA3_CONTEXT_REG_ACCESS_ERROR        = 672,

	STATUS_MEMORY_U32_ACCESS_VIOLATION          = 673,
	STATUS_EBG_HEALTH_TEST_FAILURE              = 674,
	STATUS_EBG_CONTINUOUS_HEALTH_TEST_FAILURE   = 675,
	STATUS_EBG_REPETITION_COUNT_TEST_FAILURE    = 676,
	STATUS_EBG_ADAPTIVE_PROPORTION_TEST_FAILURE = 677,

	STATUS_FIPS_POLICY_VIOLATION                = 700,
	STATUS_CRYPTO_DISABLE                       = 701,
	STATUS_SYMMETRIC_KEY_READ_BAN               = 702,

	/* JTAG tap handler status */
	STATUS_INVALID_TAP_REQUEST                  = 800,
	STATUS_INVALID_FSM_TRANSITION               = 801,

	STATUS_USER_DEFINED                         = 4096,
	STATUS_LAST_ONE
};

enum ehsm_opcodes {
	BCM_CANT_USE                                = 0,
	BCM_GET_VERSION_INFO                        = 2,
	BCM_RESET                                   = 3,
	BCM_SELF_TEST                               = 4,
	BCM_CONFIGURE_DMA                           = 6,
	BCM_GET_SYSTEM_STATE                        = 7,
	BCM_GET_CONTEXT_INFO                        = 8,
	BCM_LOAD_ENGINE_CONTEXT                     = 9,
	BCM_STORE_ENGINE_CONTEXT                    = 10,
	BCM_PURGE_CONTEXT_CACHE                     = 11,
	BCM_AES_INIT                                = 12,
	BCM_AES_ZEROIZE                             = 13,
	BCM_AES_PROCESS                             = 14,
	BCM_AES_LOAD_IV                             = 15,
	BCM_AES_LOAD_KEY                            = 16,
	BCM_AES_KEY_GEN                             = 17,
	BCM_HASH_INIT                               = 18,
	BCM_HASH_ZEROIZE                            = 19,
	BCM_HASH_UPDATE                             = 20,
	BCM_HASH_FINAL                              = 21,
	BCM_HMAC_INIT                               = 22,
	BCM_HMAC_ZEROIZE                            = 23,
	BCM_HMAC_UPDATE                             = 24,
	BCM_HMAC_FINAL                              = 25,
	BCM_HMAC_LOAD_KEY                           = 26,
	BCM_HMAC_KEY_GEN                            = 27,
	BCM_DRBG_GEN_RAN_BITS                       = 28,

	BCM_DRBG_RESEED                             = 30,
	BCM_OTP_WRITE                               = 31,
	BCM_OTP_READ                                = 32,
	BCM_RSASSA_PKCS_V15_VERIFY_INIT             = 33,
	BCM_RSASSA_PKCS_V15_VERIFY_UPDATE           = 34,
	BCM_RSASSA_PKCS_V15_VERIFY_FINAL            = 35,
	BCM_RSASSA_PKCS_V15_VERIFY                  = 36,
	BCM_MC_INIT                                 = 37,
	BCM_MC_READ                                 = 39,
	CM_FW_AUTHORIZE                             = 41,
	BCM_EC_ZEROIZE                              = 42,
	BCM_EC_POINT_MULTIPLY                       = 49,
	BCM_EC_POINT_ADD                            = 50,
	BCM_EC_POINT_SUBTRACT                       = 51,
	BCM_EC_ADDITIVE_INVERSION                   = 52,
	BCM_EC_POINT_DOUBLE                         = 53,
	BCM_ZMODP_ZEROIZE                           = 54,
	BCM_ZMODP_PRECOMP_PARAM                     = 56,
	BCM_ZMODP_MULT_INVERSE                      = 58,
	BCM_ZMODP_MODULAR_MULTIPLY                  = 59,
	BCM_ZMODP_MODULAR_EXPONENTIATE              = 60,
	BCM_SLEEP                                   = 61,
	BCM_ZMODP_MODULAR_ADD                       = 62,
	BCM_ZMODP_MODULAR_SUBTRACT                  = 63,
	BCM_DRBG_INSTANTIATE                        = 64,
	BCM_DRBG_GENERATE                           = 65,
	BCM_RESUME                                  = 66,
	BCM_AESX_LOAD_KEY                           = 67,
	BCM_AESX_LOAD_IV                            = 68,
	BCM_AESX_INIT                               = 69,
	BCM_AESX_PROCESS                            = 71,
	BCM_AUTHENTICATED_COMMAND                   = 75,
	BCM_TWO_FACTOR_FW_AUTHORIZE                 = 76,
	BCM_RSASSA_PKCS1_V15_TWO_FACTOR_VERIFY      = 77,
	BCM_PLATFORM_GET_VERSION_INFO		    = 79,
	BCM_AES_KEYWRAP_ENCRYPT_PROCESS             = 130,
	BCM_AES_KEYWRAP_DECRYPT_PROCESS             = 131,
	BCM_ECDSA_SIGN                              = 135,
	BCM_ECDSA_VERIFY                            = 136,

	BCM_DES_INIT                                = 157,
	BCM_DES_LOAD_IV                             = 158,
	BCM_DES_LOAD_KEY                            = 159,
	BCM_DES_PROCESS                             = 160,
	BCM_DES_ZEROIZE                             = 161,
	BCM_AES_GCM_INIT                            = 162,

	/* PIE KEM OTP Provision Service */
	PIE_RKEK_PROTECTED_PROVISION                = 201,
	PIE_RSA_OAEP_ENCRYPT                        = 202,
	PIE_RSA_OAEP_ENCRYPT_SESSION_KEY            = 203,
	PIE_RSA_OAEP_DECRYPT                        = 204,

	BCM_DRBG_UNINSTANTIATE_CMD                  = 300,
	BCM_GET_ENTROPY                             = 301,

	BCM_RSADSA_PSS_SIGN                         = 312,

	BCM_RSADSA_PSS_VERIFY                       = 314,

	EHSM_LCS_ADVANCE                            = 500,
	EHSM_RKEK_PROVISION                         = 501,
	EHSM_BOOT_PORT_DISABLE                      = 502,
	EHSM_SECURE_BOOT_PROVISION                  = 503,
	EHSM_ENCRYPTED_BOOT_PROVISION               = 504,
	EHSM_MEASURED_BOOT_PROVISION                = 505,
	EHSM_DEBUG_PORT_DISABLE                     = 506,
	EHSM_IROM_SECURITY_MODE_PROVISION           = 507,
	EHSM_IROMM_BOOT_CONFIG_PROVISION            = 508,
	EHSM_OEM_BLOCK_PROVISION                    = 509,
	EHSM_OEM_BLOCK_LOCK                         = 510,
	EHSM_OEM_BLOCK_READ                         = 511,
	EHSM_EBG_HEALTH_TEST_CUTOFF_VALUE_PROVISION = 512,
	EHSM_SET_OTP_PROGRAMMING_DURATION           = 513,
	EHSM_PUF_UDS_ACTIVATION                     = 514,
	EHSM_BOOTROM_RESERVED_PARAMETER_PROVISION   = 515,
	EHSM_DEVICE_KEY_MIXER_PROVISION             = 516,
	EHSM_DEVICE_KEY_MIXER_DISABLE               = 517,
	EHSM_EFUSE_DISABLE                          = 518,
	EHSM_PUF_OTP_DUMP                           = 519,

	/* Primitives for encrypted boot */
	EHSM_ENCRYPTED_BOOT_LOAD_KEY                = 530,
	EHSM_ENCRYPTED_BOOT_INIT                    = 531,
	EHSM_ENCRYPTED_BOOT_UNWRAP_KEY              = 532,

	/* Primitives for measured boot */
	EHSM_MEASURED_BOOT_LOAD_UDS                 = 540,
	EHSM_MEASURED_BOOT_LOAD_UDS_LOCK            = 541,
	EHSM_DICE_INIT                              = 542,
	EHSM_DICE_UPDATE                            = 543,
	EHSM_DICE_FINAL                             = 544,
	EHSM_GET_MEASUREMENT_DIGESTS                = 545,
	EHSM_GET_MEASUREMENTS                       = 546,

	EHSM_SECURE_BOOT_AUTHENTICATION             = 550,
	EHSM_PIE_SECURE_LOAD                        = 551,
	EHSM_PIE_UNLOAD                             = 552,
	EHSM_KEY_MANIFEST_INSTALL                   = 553,
	EHSM_GET_CHALLENGE                          = 554,
	EHSM_AUTH_CMD                               = 555,
	EHSM_KEY_MANIFEST_LOCK                      = 556,
	EHSM_GET_CMD_PACKET_SIZE                    = 558,
	EHSM_PIE_LOCK                               = 559,

	EHSM_SHAKE_INIT                             = 570,
	EHSM_SHAKE_UPDATE                           = 571,
	EHSM_SHAKE_FINAL                            = 572,
	EHSM_SHAKE_ZEROIZE                          = 573,
	EHSM_HASH_ALL_IN_ONE                        = 574,
	EHSM_HMAC_ALL_IN_ONE                        = 575,

	BCM_SM4_INIT                                = 576,
	BCM_SM4_ZEROIZE                             = 577,
	BCM_SM4_PROCESS                             = 578,
	BCM_SM4_LOAD_IV                             = 579,
	BCM_SM4_LOAD_KEY                            = 580,
	BCM_SM4_KEY_GEN                             = 581,

	EHSM_OTP_RESET                              = 700,
	EHSM_AMC_PLAINTEXT_KEY_LOAD                 = 701,
	EHSM_DUMMY_CMD                              = 0xFFFFFFFF,
};

struct ehsm_command {
	uint32_t args[EHSM_NUM_ARGS];
	uint32_t opcode;
	uint32_t reserved[15];
	uint32_t ret_status;
	uint32_t ret_params[EHSM_NUM_ARGS];
};

/** Linked-list struct */
struct ehsm_dtd {
	unsigned long transfer_addr;
	unsigned long transfer_size;
	struct ehsm_dtd *next;
	uint64_t reserved2;
};

struct ehsm_handle {
	/* Base register address for EHSM */
	uint32_t	    *ehsm_base;
	uint32_t            last_ehsm_status;
	uint32_t            mbox;        /* Mailbox number */
	uintptr_t           mbox_offset;
	struct ehsm_command *ehsm_cmd;
	uintptr_t           host_int_reg;
	uintptr_t           cmd_status_reg;
	uint32_t            cmd_buf_full_mask;
	unsigned int        ehsm_ready:1;
	unsigned int        initialized:1;
};

/*
 * @param[in]   addr
 * @return      1 if aligned, 0 if not aligned
 */
static inline int ehsm_is_aligned(uint32_t addr)
{
	return !(addr % EHSM_ALIGNMENT);
}

/*
 * @param[in]   handle  Pointer to eHSM handle
 *
 * @return      32-bit status code output by eHSM hardware
 */
static inline uint32_t ehsm_get_last_status(const struct ehsm_handle *handle)
{
	return handle->last_ehsm_status;
}

/*
 * @param[in]   ptr
 * @return      1 if aligned, 0 if not aligned
 */
static inline int ehsm_ptr_is_aligned(const void *ptr)
{
	return !((unsigned long)ptr % EHSM_ALIGNMENT);
}

/*
 * Initializes the handle and prepares the eHSM for access
 *
 * @param[out]  handle  pointer to handle
 * @param       mailbox number to use
 *
 * @return      status
 */
int ehsm_initialize(struct ehsm_handle *handle, unsigned int mbox);

/*
 * Returns if the handle has been initialized or not.
 *
 * @param[in]   handle  handle to check
 *
 * @returns     0 if not initialized, 1 if initialized
 */
static inline int ehsm_is_initialized(const struct ehsm_handle *handle)
{
	return handle->initialized;
}

/*
 * clear a command to the eHSM
 *
 * @param	cmd	pointer to command data structure
 */
void ehsm_clear_command(struct ehsm_command *cmd);

/*
 * Send a command to the eHSM and wait for a response
 *
 * @param       handle  pointer to eHSM handle
 * @param       cmd     pointer to command data structure
 *
 * @return      Return status of command from the hardware
 */
enum ehsm_status ehsm_command(struct ehsm_handle *handle,
			      struct ehsm_command *cmd);
#endif /* __EHSM_H__ */
