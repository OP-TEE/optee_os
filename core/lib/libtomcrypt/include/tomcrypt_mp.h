/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TOMCRYPT_MP_H_
#define TOMCRYPT_MP_H_

#if defined(_CFG_CORE_LTC_ACIPHER)
void init_mp_tomcrypt(void);
#else
static inline void init_mp_tomcrypt(void) { }
#endif

#endif /* TOMCRYPT_MP_H_ */
