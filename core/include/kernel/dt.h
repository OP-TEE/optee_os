/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KERNEL_DT_H
#define KERNEL_DT_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>

#if defined(CFG_DT)

/*
 * DT-aware drivers
 */

struct dt_device_match {
	const char *compatible;
};

struct dt_driver {
	const char *name;
	const struct dt_device_match *match_table; /* null-terminated */
	const void *driver;
};

#define __dt_driver __attribute__((__section__(".rodata.dtdrv")))

const struct dt_driver *dt_find_driver(const char *compatible);

const struct dt_driver *__dt_driver_start(void);

const struct dt_driver *__dt_driver_end(void);

#define for_each_dt_driver(drv) \
	for (drv = __dt_driver_start(); drv < __dt_driver_end(); drv++)

#else

static inline const struct dt_driver *dt_find_driver(const char *compatible
						     __unused)
{
	return NULL;
}

static inline const struct dt_driver *__dt_driver_start(void)
{
	return NULL;
}

static inline const struct dt_driver *__dt_driver_end(void)
{
	return NULL;
}

#define for_each_dt_driver(drv) if (0)

#define __dt_driver

#endif /* !CFG_DT */

#endif /* KERNEL_DT_H */
