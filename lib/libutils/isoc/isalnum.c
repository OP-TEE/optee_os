// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, KAIST
 */
#include <ctype.h>

int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}
