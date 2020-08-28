/**
 * \file rsa.h
 *
 * \brief This file provides an API for the RSA public-key cryptosystem.
 *
 * The RSA public-key cryptosystem is defined in <em>Public-Key
 * Cryptography Standards (PKCS) #1 v1.5: RSA Encryption</em>
 * and <em>Public-Key Cryptography Standards (PKCS) #1 v2.1:
 * RSA Cryptography Specifications</em>.
 *
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  Copyright (C) 2019, NXP, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_RSA_ALT)
#include <fsl_sss_api.h>

typedef struct
{
    int ver;    /*!<  Always 0.*/
    size_t len; /*!<  The size of \p N in Bytes. */

    mbedtls_mpi N; /*!<  The public modulus. */
    mbedtls_mpi E; /*!<  The public exponent. */

    mbedtls_mpi D; /*!<  The private exponent. */
    mbedtls_mpi P; /*!<  The first prime factor. */
    mbedtls_mpi Q; /*!<  The second prime factor. */

    mbedtls_mpi DP; /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi DQ; /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi QP; /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi RN; /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi RP; /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi RQ; /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi Vi; /*!<  The cached blinding value. */
    mbedtls_mpi Vf; /*!<  The cached un-blinding value. */

    int padding; /*!< Selects padding mode:
                                     #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                     #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int hash_id; /*!< Hash identifier of mbedtls_md_type_t type,
                                     as specified in md.h for use in the MGF
                                     mask generating function used in the
                                     EME-OAEP and EMSA-PSS encodings. */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex; /*!<  Thread-safety mutex. */
#endif

    /** Reference to object mapped between SSS Layer        */
    sss_object_t *pSSSObject;
} mbedtls_rsa_context;

#endif /* MBEDTLS_RSA_ALT */
