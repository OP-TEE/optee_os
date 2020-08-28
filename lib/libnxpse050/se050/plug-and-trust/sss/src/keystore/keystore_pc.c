/*
 * Copyright 2018-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Key store in PC : For testing */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <fsl_sss_keyid_map.h>

#if SSS_HAVE_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#endif

#if SSS_HAVE_OPENSSL
#include <fsl_sss_openssl_types.h>
#endif

#include <nxEnsure.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxLog_sss.h"
#include "sm_types.h"

#if (defined(MBEDTLS_FS_IO) && !AX_EMBEDDED) || SSS_HAVE_OPENSSL

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* File allocation table file name */
#define FAT_FILENAME "sss_fat.bin"
#define MAX_FILE_NAME_SIZE 255

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

// keyStoreTable_t gKeyStoreShadow;
// keyIdAndTypeIndexLookup_t gLookupEntires[KS_N_ENTIRES];

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/* For the key sss_key, what will the file name look like */
void ks_sw_getKeyFileName(
    char *const file_name, const size_t size, const sss_object_t *sss_key, const char *root_folder)
{
    uint32_t keyId      = sss_key->keyId;
    uint16_t keyType    = sss_key->objectType;
    uint16_t cipherType = sss_key->cipherType;
    SNPRINTF(file_name, size - 1, "%s/sss_%08X_%04d_%04d.bin", root_folder, keyId, keyType, cipherType);
}

void ks_sw_fat_allocate(keyStoreTable_t **keystore_shadow)
{
    keyStoreTable_t *pKeyStoreShadow = SSS_MALLOC(sizeof(keyStoreTable_t));
    if (pKeyStoreShadow == NULL) {
        LOG_E("Error in pKeyStoreShadow mem allocation");
        return;
    }
    keyIdAndTypeIndexLookup_t *ppLookupEntires = SSS_MALLOC(KS_N_ENTIRES * sizeof(keyIdAndTypeIndexLookup_t));
    //for (int i = 0; i < KS_N_ENTIRES; i++) {
    //    ppLookupEntires[i] = calloc(1, sizeof(keyIdAndTypeIndexLookup_t));
    //}
    memset(ppLookupEntires, 0, (KS_N_ENTIRES * sizeof(keyIdAndTypeIndexLookup_t)));
    ks_common_init_fat(pKeyStoreShadow, ppLookupEntires, KS_N_ENTIRES);
    *keystore_shadow = pKeyStoreShadow;
}

void ks_sw_fat_free(keyStoreTable_t *keystore_shadow)
{
    if (NULL != keystore_shadow) {
        if (NULL != keystore_shadow->entries) {
            //for (int i = 0; i < keystore_shadow->maxEntries; i++) {
            //    free(keystore_shadow->entries[i]);
            //}
            SSS_FREE(keystore_shadow->entries);
        }
        memset(keystore_shadow, 0, sizeof(*keystore_shadow));
        SSS_FREE(keystore_shadow);
    }
}

void ks_sw_fat_remove(const char *szRootPath)
{
    char file_name[MAX_FILE_NAME_SIZE];
    FILE *fp = NULL;
    SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath);
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        /* OK. File does not exist. */
    }
    else {
        fclose(fp);
#ifdef _WIN32
        _unlink(file_name);
#else
        unlink(file_name);
#endif
    }
}

static sss_status_t ks_sw_fat_update(keyStoreTable_t *keystore_shadow, const char *szRootPath)
{
    sss_status_t retval = kStatus_SSS_Success;
    char file_name[MAX_FILE_NAME_SIZE];
    FILE *fp = NULL;
    SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath);
    fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        LOG_E("Can not open the file");
        retval = kStatus_SSS_Fail;
    }
    else {
        fseek(fp, 0, SEEK_SET);
        fwrite(keystore_shadow, sizeof(*keystore_shadow), 1, fp);
        fwrite(keystore_shadow->entries, sizeof(*keystore_shadow->entries) * keystore_shadow->maxEntries, 1, fp);
        fclose(fp);
    }
    return retval;
}

#if defined(MBEDTLS_FS_IO)
sss_status_t ks_mbedtls_fat_update(sss_mbedtls_key_store_t *keyStore)
{
    return ks_sw_fat_update(keyStore->keystore_shadow, keyStore->session->szRootPath);
}
#endif

#if SSS_HAVE_OPENSSL
sss_status_t ks_openssl_fat_update(sss_openssl_key_store_t *keyStore)
{
    return ks_sw_fat_update(keyStore->keystore_shadow, keyStore->session->szRootPath);
}
#endif

sss_status_t ks_sw_fat_load(const char *szRootPath, keyStoreTable_t *pKeystore_shadow)
{
    sss_status_t retval = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE];
    FILE *fp = NULL;
    size_t ret;
    ENSURE_OR_GO_CLEANUP(pKeystore_shadow);
    keyStoreTable_t fileShadow;
    SNPRINTF(file_name, sizeof(file_name), "%s/" FAT_FILENAME, szRootPath);
    fp = fopen(file_name, "rb");
    if (fp == NULL) {
        /* File did not exist, and it's OK most of the time
         * because the test code comes through this path.
         * hence return fail, but do not log any message. */
        return kStatus_SSS_Fail;
    }

    ret = fread(&fileShadow, 1, sizeof(fileShadow), fp);
    if (ret > 0 && fileShadow.maxEntries == pKeystore_shadow->maxEntries &&
        fileShadow.magic == pKeystore_shadow->magic && fileShadow.version == pKeystore_shadow->version) {
        ret =
            fread(pKeystore_shadow->entries, 1, sizeof(*pKeystore_shadow->entries) * pKeystore_shadow->maxEntries, fp);
        if (ret > 0) {
            retval = kStatus_SSS_Success;
        }
    }
    else {
        LOG_E("ERROR! keystore_shadow != pKeystore_shadow");
    }
    fclose(fp);
cleanup:
    return retval;
}

#if defined(MBEDTLS_FS_IO)
sss_status_t ks_mbedtls_load_key(sss_mbedtls_object_t *sss_key, keyStoreTable_t *keystore_shadow, uint32_t extKeyId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE];
    FILE *fp = NULL;
    //const char *root_folder = sss_key->keyStore->session->szRootPath;
    size_t size = 0;
    uint32_t i;
    keyIdAndTypeIndexLookup_t *shadowEntry = NULL;

    for (i = 0; i < sss_key->keyStore->max_object_count; i++) {
        if (keystore_shadow->entries[i].extKeyId == extKeyId) {
            shadowEntry         = &keystore_shadow->entries[i];
            sss_key->keyId      = shadowEntry->extKeyId;
            sss_key->cipherType = shadowEntry->cipherType;
            sss_key->objectType = (shadowEntry->keyPart & 0x0F);

            ks_sw_getKeyFileName(
                file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
            retval = kStatus_SSS_Success;
            break;
        }
    }
    if (retval == kStatus_SSS_Success) {
        fp = fopen(file_name, "rb");
        if (fp == NULL) {
            LOG_E("Can not open file");
            retval = kStatus_SSS_Fail;
        }
        else {
            /* Buffer to hold max RSA Key*/
            uint8_t keyBuf[3000];
            int signed_val = 0;
            fseek(fp, 0, SEEK_END);
            signed_val = ftell(fp);
            if (signed_val < 0) {
                LOG_E("File does not contain any data");
                retval = kStatus_SSS_Fail;
                fclose(fp);
                return retval;
            }
            size = (size_t)signed_val;
            fseek(fp, 0, SEEK_SET);
            signed_val = (int)fread(keyBuf, size, 1, fp);
            if (signed_val < 0) {
                LOG_E("fread faild");
                retval = kStatus_SSS_Fail;
                fclose(fp);
                return retval;
            }
            fclose(fp);
            retval = ks_mbedtls_key_object_create(sss_key,
                shadowEntry->extKeyId,
                (shadowEntry->keyPart & 0x0F),
                shadowEntry->cipherType,
                size,
                kKeyObject_Mode_Persistent);
            if (retval == kStatus_SSS_Success)
                retval = sss_mbedtls_key_store_set_key(
                    sss_key->keyStore, sss_key, keyBuf, size, size * 8 /* FIXME */, NULL, 0);
        }
    }
    return retval;
}

sss_status_t ks_mbedtls_store_key(const sss_mbedtls_object_t *sss_key)
{
    sss_status_t retval = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE];
    FILE *fp = NULL;
    ks_sw_getKeyFileName(
        file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
    fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        LOG_E(" Can not open the file");
        retval = kStatus_SSS_Fail;
    }
    else {
        /* Buffer to hold max RSA Key*/
        uint8_t key_buf[3000];
        int ret          = 0;
        unsigned char *c = key_buf;
        memset(key_buf, 0, sizeof(key_buf));
        mbedtls_pk_context *pk;
        pk = (mbedtls_pk_context *)sss_key->contents;
        switch (sss_key->objectType) {
        case kSSS_KeyPart_Default:
            fwrite(sss_key->contents, sss_key->contents_max_size, 1, fp);
            retval = kStatus_SSS_Success; /* Allows to skip writing pem/der files */
            break;
        case kSSS_KeyPart_Pair:
        case kSSS_KeyPart_Private:
            ret = mbedtls_pk_write_key_der(pk, key_buf, sizeof(key_buf));
            break;
        case kSSS_KeyPart_Public:
            ret = mbedtls_pk_write_pubkey_der(pk, key_buf, sizeof(key_buf));
            break;
        }
        if (ret > 0 && retval != kStatus_SSS_Success) {
            c = key_buf + sizeof(key_buf) - ret;
            fwrite(c, ret, 1, fp);
            retval = kStatus_SSS_Success;
        }
        fflush(fp);
        fclose(fp);
    }
    return retval;
}

#ifdef _MSC_VER
#define UNLINK _unlink
#else
#define UNLINK unlink
#endif

sss_status_t ks_mbedtls_remove_key(const sss_mbedtls_object_t *sss_key)
{
    sss_status_t retval = kStatus_SSS_Fail;
    char file_name[MAX_FILE_NAME_SIZE];
    ks_sw_getKeyFileName(
        file_name, sizeof(file_name), (const sss_object_t *)sss_key, sss_key->keyStore->session->szRootPath);
    if (0 == UNLINK(file_name)) {
        retval = kStatus_SSS_Success;
    }
    return retval;
}
#endif

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

#endif /* MBEDTLS_FS_IO */
