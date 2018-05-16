/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef SYS_CDEFS_H
#define SYS_CDEFS_H

/*
 * GCC 2.95 provides `__restrict' as an extension to C90 to support the
 * C99-specific `restrict' type qualifier.  We happen to use `__restrict' as
 * a way to define the `restrict' type qualifier without disturbing older
 * software that is unaware of C99 keywords.
 */
#if !(__GNUC__ == 2 && __GNUC_MINOR__ == 95)
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901 || defined(lint)
#define __restrict
#else
#define __restrict      restrict
#endif
#endif

#define __always_inline	__attribute__((always_inline)) inline

#endif /*SYS_CDEFS_H*/
