// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, EPAM Systems
 */

#include <compiler.h>

unsigned long int __getauxval (unsigned long int type);
unsigned long int __getauxval (unsigned long int type __unused)
{
	return 0;
}
