/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Mapping between key id and physical key store */

#ifndef SSS_INC_KEYID_MAP_H_
#define SSS_INC_KEYID_MAP_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <fsl_sss_api.h>

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* Physical index */
/* clang-format off */
#define K_INDEX_MASK    (0xFFFFu << 0u)
#define K_TYPE_MASK     (0xFFu << 24u)
#define K_TYPE_ECC_KP   (0x01u << 24u)
#define K_TYPE_ECC_PUB  (0x02u << 24u)
#define K_TYPE_AES      (0x03u << 24u)
#define K_TYPE_CERT     (0x04u << 24u)

/* Key store N Count */
#define KS_N_ECC_KEY_PAIRS  4
#define KS_N_ECC_PUB_KEYS   3
#define KS_N_AES_KEYS       8
#define KS_N_CERTIFCATES    4
#define KS_N_RSA_KEY_PAIRS  1
#define KS_N_SYM_KEYS       1

/* clang-format on */

#define KS_N_ENTIRES_CL (0 + KS_N_RSA_KEY_PAIRS + KS_N_SYM_KEYS)

#define KS_N_ENTIRES (0 + KS_N_ECC_KEY_PAIRS + KS_N_ECC_PUB_KEYS + KS_N_AES_KEYS + KS_N_CERTIFCATES)

#define KEYSTORE_MAGIC (0xA71C401L)
#define KEYSTORE_VERSION (0x0004)
/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/* Generic entry of a Key ID Mapping inside the secure element */
typedef struct
{
    /** External index */
    uint32_t extKeyId;

    /* Of type sss_key_part_t
     *
     * B0,B1,B2,B3 -> Key part  and  B4,B5,B6,B7 -> (No of slots taken - 1) */
    uint8_t keyPart;
    uint8_t accessPermission;
    uint8_t cipherType; /* Of type sss_cipher_type_t */
    /** Internal index */
    uint8_t keyIntIndex;
} keyIdAndTypeIndexLookup_t;

typedef struct _keyStoreTable_t
{
    /** Fixed - Unique 32bit magic number.
     *
     * In case some one over-writes we can know. */
    uint32_t magic;
    /** Fixed - constant based on version number */
    uint16_t version;
    /**
     * maxEntries  Fixed - constant in the Layout. Should be equal to
     * KS_N_ENTIRES This will help in porting between A71CH with less memory and
     * SE050 with more memory
     */
    uint16_t maxEntries;
    /** Dynamic entries */
    keyIdAndTypeIndexLookup_t *entries;
} keyStoreTable_t;

/* ************************************************************************** */
/* Global Variables                                                            */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

/**
 * Initialize the File allocation table entry
 *
 * @param keystore_shadow Shadow structure (to be persisted later to EEPROM or
 * File System)
 * @param lookup_entires Mapping table
 * @param max_entries Maximum entries that the Key Store can have
 */
void ks_common_init_fat(
    keyStoreTable_t *keystore_shadow, keyIdAndTypeIndexLookup_t *lookup_entires, size_t max_entries);

/**
 * Update the File Allocation Table for the key.
 *
 * @param[out] keystore_shadow
 * @param[in] sss_key The key object.
 * @param[in] intIndex internal index.
 * @param extId External 32bit id of the key
 * @param object_type Type of the object
 * @param intIndex Internal index of the key.
 * @param accessPermission Access (Read/write/etc.)
 *
 * @note accessPermission is not used for A71CH
 *
 * @return Fail if not able to add the entry.

 */
sss_status_t ks_common_update_fat(keyStoreTable_t *keystore_shadow,
    uint32_t extId,
    sss_key_part_t object_part,
    sss_cipher_type_t cipher_type,
    uint8_t intIndex,
    uint32_t accessPermission,
    uint16_t keyLen);

/**
 * check if the internal slot is availble for the key type.
 *
 * @param[in] keystore_shadow
 * @param[in] object_type type of key Object
 * @param[out] next_free_index avialable internal index for a particular key
 * type
 *
 * @return Fail if internal index is not available.
 */
sss_status_t ks_common_check_available_int_index(keyStoreTable_t *keystore_shadow,
    uint8_t object_type,
    uint8_t cipher_type,
    uint16_t *next_free_index,
    uint16_t keyLen);

sss_status_t ks_common_extId_to_int_index(keyStoreTable_t *keystore_shadow, uint32_t extId, uint16_t *intIndex);
/**
 * check if the key store is valid.
 *
 * @param[in] keystore_shadow The shadow of keystore
 * @param[out] status
 *
 * @return Fail if key store is not valid
 */
sss_status_t isValidKeyStoreShadow(keyStoreTable_t *keystore_shadow);
/**
* check if the internal slot is availble for the key type.
*
* @param[in] keystore_shadow
* @param[in] keyId key id for getting key object
* @param[out] keyType type of keyobject retrieved from keyId* type
*
* @return Fail if keyId not found
*/
sss_status_t ks_common_get_keyType_from_keyid(
    keyStoreTable_t *keystore_shadow, uint32_t keyId, uint32_t *keyType, uint32_t *cipherType);
/**
 * remove entry from shadow keystore.
 *
 * @param[in] keystore_shadow
 * @param[in] extId key id for getting key object
 *
 * @return Fail if keyId not found
 */
sss_status_t ks_common_remove_fat(keyStoreTable_t *keystore_shadow, uint32_t extId);

void ks_sw_fat_remove(const char *szRootPath);
void ks_sw_fat_free(keyStoreTable_t *keystore_shadow);
void ks_sw_fat_allocate(keyStoreTable_t **keystore_shadow);
void ks_sw_getKeyFileName(
    char *const file_name, const size_t size, const sss_object_t *sss_key, const char *root_folder);
sss_status_t ks_sw_fat_load(const char *szRootPath, keyStoreTable_t *pKeystore_shadow);

#endif /* SSS_INC_KEYID_MAP_H_ */
