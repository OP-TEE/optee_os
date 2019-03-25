// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, KAIST
 */
#include <ctype.h>

int ispunct(int c)
{
    return isgraph(c) && !isalnum(c);
}
