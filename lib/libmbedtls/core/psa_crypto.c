/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "../../core/include/crypto/crypto.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#include "check_crypto_config.h"
#endif

#include <../mbedtls/library/psa_crypto_core.h>
#include "../mbedtls/library/psa_crypto_invasive.h"
#include "../mbedtls/library/psa_crypto_driver_wrappers_no_static.h"
#include "../mbedtls/library/psa_crypto_ecp.h"
#include "../mbedtls/library/psa_crypto_ffdh.h"
#include "../mbedtls/library/psa_crypto_hash.h"
#include "../mbedtls/library/psa_crypto_mac.h"
#include "../mbedtls/library/psa_crypto_rsa.h"
#include "../mbedtls/library/psa_crypto_slot_management.h"
#include "../mbedtls/library/psa_crypto_driver_wrappers.h"
#include "../mbedtls/library/psa_crypto_cipher.h"
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#include "psa_crypto_se.h"
#endif

/* Include internal declarations that are useful for implementing persistently
 * stored keys. */
#include "../mbedtls/library/psa_crypto_storage.h"

#include "../mbedtls/library/psa_crypto_random_impl.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"

#include "mbedtls/aes.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md5.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/psa_util.h"
#include "mbedtls/threading.h"

psa_status_t psa_generate_key_proxy(const psa_key_attributes_t *attributes,
                                    mbedtls_svc_key_id_t *key) {
    return psa_generate_key(attributes, key);
}
#define MBEDTLS_PSA_CIPHER_OPERATION_INIT { 0, 0, 0, { 0 } }

psa_cipher_operation_t psa_cipher_operation_init_proxy(void) {

        const struct psa_cipher_operation_s v = MBEDTLS_PSA_CIPHER_OPERATION_INIT;
        return v;

}

psa_status_t psa_cipher_encrypt_setup_proxy(psa_cipher_operation_t *operation,
                                            mbedtls_svc_key_id_t key,
                                            psa_algorithm_t alg) {
    return psa_cipher_encrypt_setup(operation, key, alg);
}

psa_status_t psa_cipher_decrypt_setup_proxy(psa_cipher_operation_t *operation,
                                            mbedtls_svc_key_id_t key,
                                            psa_algorithm_t alg) {
    return psa_cipher_decrypt_setup(operation, key, alg);
}

psa_status_t psa_cipher_generate_iv_proxy(psa_cipher_operation_t *operation,
                                          uint8_t *iv,
                                          size_t iv_size,
                                          size_t *iv_length) {
    return psa_cipher_generate_iv(operation, iv, iv_size, iv_length);
}

psa_status_t psa_cipher_set_iv_proxy(psa_cipher_operation_t *operation,
                                     const uint8_t *iv,
                                     size_t iv_length) {
    return psa_cipher_set_iv(operation, iv, iv_length);
}

psa_status_t psa_cipher_update_proxy(psa_cipher_operation_t *operation,
                                     const uint8_t *input,
                                     size_t input_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length) {
    return psa_cipher_update(operation, input, input_length, output, output_size, output_length);
}

psa_status_t psa_cipher_finish_proxy(psa_cipher_operation_t *operation,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length) {
    return psa_cipher_finish(operation, output, output_size, output_length);
}

psa_status_t psa_cipher_abort_proxy(psa_cipher_operation_t *operation) {
    return psa_cipher_abort(operation);
}

psa_status_t psa_aead_encrypt_proxy(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *nonce,
                                    size_t nonce_length,
                                    const uint8_t *additional_data,
                                    size_t additional_data_length,
                                    const uint8_t *plaintext,
                                    size_t plaintext_length,
                                    uint8_t *ciphertext,
                                    size_t ciphertext_size,
                                    size_t *ciphertext_length) {
    return psa_aead_encrypt(key, alg, nonce, nonce_length, additional_data,
                            additional_data_length, plaintext, plaintext_length,
                            ciphertext, ciphertext_size, ciphertext_length);
}

psa_status_t psa_aead_decrypt_proxy(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *nonce,
                                    size_t nonce_length,
                                    const uint8_t *additional_data,
                                    size_t additional_data_length,
                                    const uint8_t *ciphertext,
                                    size_t ciphertext_length,
                                    uint8_t *plaintext,
                                    size_t plaintext_size,
                                    size_t *plaintext_length) {
    return psa_aead_decrypt(key, alg, nonce, nonce_length, additional_data,
                            additional_data_length, ciphertext, ciphertext_length,
                            plaintext, plaintext_size, plaintext_length);
}

psa_aead_operation_t psa_aead_operation_init_proxy(void) {
    return psa_aead_operation_init();
}

psa_status_t psa_aead_encrypt_setup_proxy(psa_aead_operation_t *operation,
                                          mbedtls_svc_key_id_t key,
                                          psa_algorithm_t alg) {
    return psa_aead_encrypt_setup(operation, key, alg);
}

psa_status_t psa_aead_decrypt_setup_proxy(psa_aead_operation_t *operation,
                                          mbedtls_svc_key_id_t key,
                                          psa_algorithm_t alg) {
    return psa_aead_decrypt_setup(operation, key, alg);
}

psa_status_t psa_aead_generate_nonce_proxy(psa_aead_operation_t *operation,
                                           uint8_t *nonce,
                                           size_t nonce_size,
                                           size_t *nonce_length) {
    return psa_aead_generate_nonce(operation, nonce, nonce_size, nonce_length);
}

psa_status_t psa_aead_set_nonce_proxy(psa_aead_operation_t *operation,
                                      const uint8_t *nonce,
                                      size_t nonce_length) {
    return psa_aead_set_nonce(operation, nonce, nonce_length);
}

psa_status_t psa_aead_set_lengths_proxy(psa_aead_operation_t *operation,
                                        size_t ad_length,
                                        size_t plaintext_length) {
    return psa_aead_set_lengths(operation, ad_length, plaintext_length);
}

psa_status_t psa_aead_update_ad_proxy(psa_aead_operation_t *operation,
                                      const uint8_t *input,
                                      size_t input_length) {
    return psa_aead_update_ad(operation, input, input_length);
}

psa_status_t psa_aead_update_proxy(psa_aead_operation_t *operation,
                                   const uint8_t *input,
                                   size_t input_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length) {
    return psa_aead_update(operation, input, input_length, output, output_size, output_length);
}

psa_status_t psa_aead_finish_proxy(psa_aead_operation_t *operation,
                                   uint8_t *ciphertext,
                                   size_t ciphertext_size,
                                   size_t *ciphertext_length,
                                   uint8_t *tag,
                                   size_t tag_size,
                                   size_t *tag_length) {
    return psa_aead_finish(operation, ciphertext, ciphertext_size, ciphertext_length, tag, tag_size, tag_length);
}

psa_status_t psa_aead_verify_proxy(psa_aead_operation_t *operation,
                                   uint8_t *plaintext,
                                   size_t plaintext_size,
                                   size_t *plaintext_length,
                                   const uint8_t *tag,
                                   size_t tag_length) {
    return psa_aead_verify(operation, plaintext, plaintext_size, plaintext_length, tag, tag_length);
}

psa_status_t psa_aead_abort_proxy(psa_aead_operation_t *operation) {
    return psa_aead_abort(operation);
}

psa_status_t psa_sign_message_proxy(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length) {
    return psa_sign_message(key, alg, input, input_length, signature, signature_size, signature_length);
}

psa_status_t psa_verify_message_proxy(mbedtls_svc_key_id_t key,
                                      psa_algorithm_t alg,
                                      const uint8_t *input,
                                      size_t input_length,
                                      const uint8_t *signature,
                                      size_t signature_length) {
    return psa_verify_message(key, alg, input, input_length, signature, signature_length);
}

psa_key_derivation_operation_t psa_key_derivation_operation_init_proxy(void) {
    return psa_key_derivation_operation_init();
}

psa_status_t psa_key_derivation_setup_proxy(psa_key_derivation_operation_t *operation,
                                            psa_algorithm_t alg) {
    return psa_key_derivation_setup(operation, alg);
}

psa_status_t psa_key_derivation_input_bytes_proxy(psa_key_derivation_operation_t *operation,
                                                  psa_key_derivation_step_t step,
                                                  const uint8_t *data,
                                                  size_t data_length) {
    return psa_key_derivation_input_bytes(operation, step, data, data_length);
}

psa_status_t psa_mac_verify_proxy(mbedtls_svc_key_id_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *input,
                                  size_t input_length,
                                  const uint8_t *mac,
                                  size_t mac_length) {
    return psa_mac_verify(key, alg, input, input_length, mac, mac_length);
}

psa_status_t psa_mac_compute_proxy(mbedtls_svc_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   uint8_t *mac,
                                   size_t mac_size,
                                   size_t *mac_length) {
    return psa_mac_compute(key, alg, input, input_length, mac, mac_size, mac_length);
}

psa_hash_operation_t psa_hash_operation_init_proxy(void) {
    return psa_hash_operation_init();
}

psa_status_t psa_hash_compute_proxy(psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    uint8_t *hash,
                                    size_t hash_size,
                                    size_t *hash_length) {
    return psa_hash_compute(alg, input, input_length, hash, hash_size, hash_length);
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
