/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


        UTEE_SYSCALL utee_return, TEE_SCN_RETURN, 1

        UTEE_SYSCALL utee_log, TEE_SCN_LOG, 2

        UTEE_SYSCALL utee_panic, TEE_SCN_PANIC, 1

        UTEE_SYSCALL utee_get_property, TEE_SCN_GET_PROPERTY, 7

        UTEE_SYSCALL utee_get_property_name_to_index, \
                TEE_SCN_GET_PROPERTY_NAME_TO_INDEX, 4

        UTEE_SYSCALL utee_open_ta_session, TEE_SCN_OPEN_TA_SESSION, 5

        UTEE_SYSCALL utee_close_ta_session, TEE_SCN_CLOSE_TA_SESSION, 1

        UTEE_SYSCALL utee_invoke_ta_command, TEE_SCN_INVOKE_TA_COMMAND, 5
        
        UTEE_SYSCALL utee_get_cancellation_flag, \
                     TEE_SCN_GET_CANCELLATION_FLAG, 1

        UTEE_SYSCALL utee_check_access_rights, TEE_SCN_CHECK_ACCESS_RIGHTS, 3

        UTEE_SYSCALL utee_unmask_cancellation, TEE_SCN_UNMASK_CANCELLATION, 1

        UTEE_SYSCALL utee_mask_cancellation, TEE_SCN_MASK_CANCELLATION, 1

        UTEE_SYSCALL utee_wait, TEE_SCN_WAIT, 1

        UTEE_SYSCALL utee_get_time, TEE_SCN_GET_TIME, 2

        UTEE_SYSCALL utee_set_ta_time, TEE_SCN_SET_TA_TIME, 1

        UTEE_SYSCALL utee_cryp_state_alloc, TEE_SCN_CRYP_STATE_ALLOC, 5

        UTEE_SYSCALL utee_cryp_state_copy, TEE_SCN_CRYP_STATE_COPY, 2

        UTEE_SYSCALL utee_cryp_state_free, TEE_SCN_CRYP_STATE_FREE, 1

        UTEE_SYSCALL utee_hash_init, TEE_SCN_HASH_INIT, 3

        UTEE_SYSCALL utee_hash_update, TEE_SCN_HASH_UPDATE, 3

        UTEE_SYSCALL utee_hash_final, TEE_SCN_HASH_FINAL, 5

        UTEE_SYSCALL utee_cipher_init, TEE_SCN_CIPHER_INIT, 3

        UTEE_SYSCALL utee_cipher_update, TEE_SCN_CIPHER_UPDATE, 5

        UTEE_SYSCALL utee_cipher_final, TEE_SCN_CIPHER_FINAL, 5

        UTEE_SYSCALL utee_cryp_obj_get_info, TEE_SCN_CRYP_OBJ_GET_INFO, 2

        UTEE_SYSCALL utee_cryp_obj_restrict_usage, \
                     TEE_SCN_CRYP_OBJ_RESTRICT_USAGE, 2

        UTEE_SYSCALL utee_cryp_obj_get_attr, TEE_SCN_CRYP_OBJ_GET_ATTR, 4

        UTEE_SYSCALL utee_cryp_obj_alloc, TEE_SCN_CRYP_OBJ_ALLOC, 3

        UTEE_SYSCALL utee_cryp_obj_close, TEE_SCN_CRYP_OBJ_CLOSE, 1

        UTEE_SYSCALL utee_cryp_obj_reset, TEE_SCN_CRYP_OBJ_RESET,  1

        UTEE_SYSCALL utee_cryp_obj_populate, TEE_SCN_CRYP_OBJ_POPULATE, 3

        UTEE_SYSCALL utee_cryp_obj_copy, TEE_SCN_CRYP_OBJ_COPY, 2

        UTEE_SYSCALL utee_cryp_derive_key, TEE_SCN_CRYP_DERIVE_KEY, 4

        UTEE_SYSCALL utee_cryp_random_number_generate, \
                     TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE, 2

        UTEE_SYSCALL utee_authenc_init, TEE_SCN_AUTHENC_INIT, 6

        UTEE_SYSCALL utee_authenc_update_aad, TEE_SCN_AUTHENC_UPDATE_AAD, 3

        UTEE_SYSCALL utee_authenc_update_payload, \
                     TEE_SCN_AUTHENC_UPDATE_PAYLOAD, 5

        UTEE_SYSCALL utee_authenc_enc_final, TEE_SCN_AUTHENC_ENC_FINAL, 7

        UTEE_SYSCALL utee_authenc_dec_final, TEE_SCN_AUTHENC_DEC_FINAL, 7

        UTEE_SYSCALL utee_asymm_operate, TEE_SCN_ASYMM_OPERATE, 7

        UTEE_SYSCALL utee_asymm_verify, TEE_SCN_ASYMM_VERIFY, 7

        UTEE_SYSCALL utee_storage_obj_open, TEE_SCN_STORAGE_OBJ_OPEN, 5

        UTEE_SYSCALL utee_storage_obj_create, TEE_SCN_STORAGE_OBJ_CREATE, 8

        UTEE_SYSCALL utee_storage_obj_del, TEE_SCN_STORAGE_OBJ_DEL, 1

        UTEE_SYSCALL utee_storage_obj_rename, TEE_SCN_STORAGE_OBJ_RENAME, 3

        UTEE_SYSCALL utee_storage_alloc_enum, TEE_SCN_STORAGE_ENUM_ALLOC, 1

        UTEE_SYSCALL utee_storage_free_enum, TEE_SCN_STORAGE_ENUM_FREE, 1

        UTEE_SYSCALL utee_storage_reset_enum, TEE_SCN_STORAGE_ENUM_RESET, 1

        UTEE_SYSCALL utee_storage_start_enum, TEE_SCN_STORAGE_ENUM_START, 2

        UTEE_SYSCALL utee_storage_next_enum, TEE_SCN_STORAGE_ENUM_NEXT, 4

        UTEE_SYSCALL utee_storage_obj_read, TEE_SCN_STORAGE_OBJ_READ, 4

        UTEE_SYSCALL utee_storage_obj_write, TEE_SCN_STORAGE_OBJ_WRITE, 3

        UTEE_SYSCALL utee_storage_obj_trunc, TEE_SCN_STORAGE_OBJ_TRUNC, 2

        UTEE_SYSCALL utee_storage_obj_seek, TEE_SCN_STORAGE_OBJ_SEEK, 3

        UTEE_SYSCALL utee_cryp_obj_generate_key, \
                     TEE_SCN_CRYP_OBJ_GENERATE_KEY, 4

        UTEE_SYSCALL utee_se_service_open, TEE_SCN_SE_SERVICE_OPEN, 1

        UTEE_SYSCALL utee_se_service_close, TEE_SCN_SE_SERVICE_CLOSE, 1

        UTEE_SYSCALL utee_se_service_get_readers, \
                TEE_SCN_SE_SERVICE_GET_READERS, 3

        UTEE_SYSCALL utee_se_reader_get_prop, \
                TEE_SCN_SE_READER_GET_PROP, 2

        UTEE_SYSCALL utee_se_reader_get_name, \
                TEE_SCN_SE_READER_GET_NAME, 3

        UTEE_SYSCALL utee_se_reader_open_session, \
                TEE_SCN_SE_READER_OPEN_SESSION, 2

        UTEE_SYSCALL utee_se_reader_close_sessions, \
                TEE_SCN_SE_READER_CLOSE_SESSIONS, 1

        UTEE_SYSCALL utee_se_session_is_closed, \
                TEE_SCN_SE_SESSION_IS_CLOSED, 1

        UTEE_SYSCALL utee_se_session_get_atr, \
                TEE_SCN_SE_SESSION_GET_ATR, 3

        UTEE_SYSCALL utee_se_session_open_channel, \
                TEE_SCN_SE_SESSION_OPEN_CHANNEL, 5

        UTEE_SYSCALL utee_se_session_close, \
                TEE_SCN_SE_SESSION_CLOSE, 1

        UTEE_SYSCALL utee_se_channel_select_next, \
                TEE_SCN_SE_CHANNEL_SELECT_NEXT, 1

        UTEE_SYSCALL utee_se_channel_get_select_resp, \
                TEE_SCN_SE_CHANNEL_GET_SELECT_RESP, 3

        UTEE_SYSCALL utee_se_channel_transmit, \
                TEE_SCN_SE_CHANNEL_TRANSMIT, 5

        UTEE_SYSCALL utee_se_channel_close, \
                TEE_SCN_SE_CHANNEL_CLOSE, 1

        UTEE_SYSCALL utee_cache_operation, TEE_SCN_CACHE_OPERATION, 3
