/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TOMCRYPT_MPA_H_
#define TOMCRYPT_MPA_H_

#if defined(_CFG_CRYPTO_WITH_ACIPHER)
void init_mpa_tomcrypt(void);
#else
static inline void init_mpa_tomcrypt(void) { }
#endif

#endif /* TOMCRYPT_MPA_H_ */
