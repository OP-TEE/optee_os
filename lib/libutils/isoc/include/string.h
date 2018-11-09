/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/*
 * This file provides what C99 standard requires for <string.h>
 * for some functions
 */

#ifndef STRING_H
#define STRING_H

#include <stddef.h>
#include <sys/cdefs.h>

void *memcpy(void *__restrict s1, const void *__restrict s2, size_t n);
void *memmove(void *s1, const void *s2, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *s, int c, size_t n);

int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t n);
char *strdup(const char *s);
char *strndup(const char *s, size_t n);
char *strchr(const char *s, int c);
char *strstr(const char *big, const char *little);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strrchr(const char *s, int i);

void *memchr(const void *buf, int c, size_t length);

#endif /* STRING_H */
