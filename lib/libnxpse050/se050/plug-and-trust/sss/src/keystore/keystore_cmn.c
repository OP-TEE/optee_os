/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Common Key store implementation between keystore_a7x and keystore_pc */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_ftr.h>
#include <fsl_sss_keyid_map.h>
#include <inttypes.h>
#include <nxLog_App.h>
#include <stdio.h>
#include <string.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#define KEYSTORE_MAGIC (0xA71C401L)
#define KEYSTORE_VERSION (0x0004)

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void ks_common_init_fat(keyStoreTable_t *keystore_shadow, keyIdAndTypeIndexLookup_t *lookup_entires, size_t max_entries)
{
    memset(keystore_shadow, 0, sizeof(*keystore_shadow));
    keystore_shadow->magic      = KEYSTORE_MAGIC;
    keystore_shadow->version    = KEYSTORE_VERSION;
    keystore_shadow->maxEntries = (uint16_t)max_entries;
    keystore_shadow->entries    = lookup_entires;
    memset(keystore_shadow->entries, 0, sizeof(*lookup_entires) * max_entries);
}

sss_status_t ks_common_update_fat(keyStoreTable_t *keystore_shadow,
    uint32_t extId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    uint8_t intIndex,
    uint32_t accessPermission,
    uint16_t keyLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    uint32_t i;
    bool found_entry         = FALSE;
    uint8_t slots_req        = 1;
    uint8_t entries_written  = 0;
    uint16_t keyLen_roundoff = 0;
    retval                   = isValidKeyStoreShadow(keystore_shadow);
    if (retval != kStatus_SSS_Success)
        goto cleanup;
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == extId) {
            LOG_W("ENTRY already exists 0x%04X", extId);
            retval      = kStatus_SSS_Fail;
            found_entry = TRUE;
            break;
        }
    }

    if (key_part == kSSS_KeyPart_Default && (cipherType == kSSS_CipherType_AES || cipherType == kSSS_CipherType_HMAC)) {
        keyLen_roundoff = ((keyLen / 16) * 16) + ((keyLen % 16) == 0 ? 0 : 16);
        slots_req       = (keyLen_roundoff / 16);
    }

    if (!found_entry) {
        retval = kStatus_SSS_Fail;
        for (i = 0; i < keystore_shadow->maxEntries; i++) {
            keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
            if (keyEntry->extKeyId == 0) {
                keyEntry->extKeyId    = extId;
                keyEntry->keyIntIndex = intIndex;
                keyEntry->keyPart     = key_part | ((slots_req - 1) << 4);
                keyEntry->cipherType  = cipherType;
                //keyEntry->accessPermission = accessPermission;

                entries_written++;
                if (entries_written == slots_req) {
                    retval = kStatus_SSS_Success;
                    break;
                }
            }
        }
    }
cleanup:
    return retval;
}

sss_status_t ks_common_remove_fat(keyStoreTable_t *keystore_shadow, uint32_t extId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    uint32_t i;
    bool found_entry = FALSE;
    retval           = isValidKeyStoreShadow(keystore_shadow);
    if (retval != kStatus_SSS_Success)
        goto cleanup;

    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry->extKeyId == extId) {
            retval = kStatus_SSS_Success;
            memset(keyEntry, 0, sizeof(keyIdAndTypeIndexLookup_t));
            found_entry = TRUE;
        }
    }
    if (!found_entry) {
        retval = kStatus_SSS_Fail;
    }
cleanup:
    return retval;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

sss_status_t keystore_shadow_From2_To_3(keyStoreTable_t *keystore_shadow)
{
    int i = 0;
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry != NULL) {
            uint16_t org_keyIntIndex = (keyEntry->cipherType) | ((keyEntry->keyIntIndex) << 8);

            switch (keyEntry->keyPart) {
            case 0:
                continue;
            case 1:
                keyEntry->keyPart    = kSSS_KeyPart_Default;
                keyEntry->cipherType = kSSS_CipherType_Certificate;
                break;
            case 2:
                keyEntry->keyPart    = kSSS_KeyPart_Default;
                keyEntry->cipherType = kSSS_CipherType_AES;
                break;
            case 3:
                keyEntry->keyPart    = kSSS_KeyPart_Default;
                keyEntry->cipherType = kSSS_CipherType_DES;
                break;
            case 4:
                keyEntry->keyPart    = kSSS_KeyPart_Default;
                keyEntry->cipherType = kSSS_CipherType_CMAC;
                break;
#if SSSFTR_RSA
            case 5:
                keyEntry->keyPart    = kSSS_KeyPart_Public;
                keyEntry->cipherType = kSSS_CipherType_RSA_CRT;
                break;
#endif
            case 6:
                keyEntry->keyPart    = kSSS_KeyPart_Public;
                keyEntry->cipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case 7:
                keyEntry->keyPart    = kSSS_KeyPart_Public;
                keyEntry->cipherType = kSSS_CipherType_EC_MONTGOMERY;
                break;
            case 8:
                keyEntry->keyPart    = kSSS_KeyPart_Public;
                keyEntry->cipherType = kSSS_CipherType_EC_TWISTED_ED;
                break;
#if SSSFTR_RSA
            case 9:
                keyEntry->keyPart    = kSSS_KeyPart_Private;
                keyEntry->cipherType = kSSS_CipherType_RSA_CRT;
                break;
#endif
            case 10:
                keyEntry->keyPart    = kSSS_KeyPart_Private;
                keyEntry->cipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case 11:
                keyEntry->keyPart    = kSSS_KeyPart_Private;
                keyEntry->cipherType = kSSS_CipherType_EC_MONTGOMERY;
                break;
            case 12:
                keyEntry->keyPart    = kSSS_KeyPart_Private;
                keyEntry->cipherType = kSSS_CipherType_EC_TWISTED_ED;
                break;
#if SSSFTR_RSA
            case 13:
                keyEntry->keyPart    = kSSS_KeyPart_Pair;
                keyEntry->cipherType = kSSS_CipherType_RSA_CRT;
                break;
#endif
            case 14:
                keyEntry->keyPart    = kSSS_KeyPart_Pair;
                keyEntry->cipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case 15:
                keyEntry->keyPart    = kSSS_KeyPart_Pair;
                keyEntry->cipherType = kSSS_CipherType_EC_MONTGOMERY;
                break;
            case 16:
                keyEntry->keyPart    = kSSS_KeyPart_Pair;
                keyEntry->cipherType = kSSS_CipherType_EC_TWISTED_ED;
                break;
            case 17:
                keyEntry->keyPart    = kSSS_KeyPart_Default;
                keyEntry->cipherType = kSSS_CipherType_UserID;
                break;
            default:
                LOG_E("Error in keystore_shadow_From2_To_3");
                return kStatus_SSS_Fail;
            }

            keyEntry->keyIntIndex = (uint8_t)org_keyIntIndex;
        }
    }

    return kStatus_SSS_Success;
}

sss_status_t keystore_shadow_From3_To_4(keyStoreTable_t *keystore_shadow)
{
    int i = 0;
    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        if (keyEntry != NULL) {
            switch (keyEntry->keyPart) {
            case kSSS_KeyPart_NONE:
                break;
            case kSSS_KeyPart_Default:
                if (keyEntry->cipherType == kSSS_CipherType_Certificate) {
                    keyEntry->cipherType = kSSS_CipherType_Binary;
                }
                break;
            default:
                LOG_E("Error in keystore_shadow_From3_To_4");
                return kStatus_SSS_Fail;
            }
        }
    }

    return kStatus_SSS_Success;
}

sss_status_t isValidKeyStoreShadow(keyStoreTable_t *keystore_shadow)
{
    sss_status_t retval = kStatus_SSS_Success;
    if (keystore_shadow != NULL) {
        if (keystore_shadow->magic != KEYSTORE_MAGIC) {
            LOG_E("Mismatch.keystore_shadow->magic and KEYSTORE_MAGIC");
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }
        if (keystore_shadow->version != KEYSTORE_VERSION) {
            if (keystore_shadow->version == 0x0002) {
                retval = keystore_shadow_From2_To_3(keystore_shadow);
                retval = keystore_shadow_From3_To_4(keystore_shadow);
            }
            else if (keystore_shadow->version == 0x0003) {
                retval = keystore_shadow_From3_To_4(keystore_shadow);
            }
            else {
                LOG_E(" Version mismatch.");
                retval = kStatus_SSS_Fail;
            }
            goto cleanup;
        }
        if (keystore_shadow->maxEntries == 0) {
            LOG_E("Keystore not yet allocated");
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        retval = kStatus_SSS_Fail;
    }
cleanup:
    return retval;
}
