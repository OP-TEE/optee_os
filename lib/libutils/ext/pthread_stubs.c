// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 */

#include <compiler.h>

#define pthread_mutex_t void

int pthread_mutex_lock(pthread_mutex_t *mutex __unused);
int pthread_mutex_unlock(pthread_mutex_t *mutex __unused);

int __weak pthread_mutex_lock(pthread_mutex_t *mutex __unused)
{
	return 0;
}

int __weak pthread_mutex_unlock(pthread_mutex_t *mutex __unused)
{
	return 0;
}
