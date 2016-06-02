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

#include <stdlib.h>
#include <utee_defines.h>
#include "image.h"

static uint32_t color_to_pixel(uint32_t color)
{
	/* Convert from ARGB to RGBA and byte swap */
	return TEE_U32_BSWAP((color >> 24) | (color << 8));
}

struct image *image_alloc(size_t width, size_t height, uint32_t color)
{
	struct image *image = malloc(sizeof(*image));
	size_t n;
	uint32_t *b;

	if (!image)
		return NULL;
	image->blen = sizeof(uint32_t) * height * width;
	image->buf = malloc(image->blen);
	if (!image->buf) {
		free(image);
		return NULL;
	}
	b = image->buf;
	image->height = height;
	image->width = width;
	for (n = 0; n < (height * width); n++)
		b[n] = color_to_pixel(color);
	return image;
}

void image_free(struct image *image)
{
	if (image) {
		free(image->buf);
		free(image);
	}
}

void *image_get_pixel_ptr(struct image *image, size_t x, size_t y)
{
	uint32_t *b = image->buf;
	size_t pos;

	if (x >= image->width || y >= image->height)
		return NULL;

	pos = y * image->width + x;
	if (pos >= image->blen)
		return NULL;

	return b + pos;
}

bool image_set_pixel(struct image *image, size_t x, size_t y, uint32_t color)
{
	uint32_t *p = image_get_pixel_ptr(image, x, y);

	if (!p)
		return false;
	*p = color_to_pixel(color);
	return true;
}

bool image_set_border(struct image *image, size_t size, uint32_t color)
{
	size_t x;
	size_t y;

	/* Size * 2 since the border appears on both sides etc */
	if (size * 2 > image->width || size * 2 > image->height)
		return false;

	/* Top horizonal line */
	for (y = 0; y < size; y++)
		for (x = 0; x < image->width; x++)
			if (!image_set_pixel(image, x, y, color))
				return false;

	/* Bottom horizonal line */
	for (y = image->height - size; y < image->height; y++)
		for (x = 0; x < image->width; x++)
			if (!image_set_pixel(image, x, y, color))
				return false;


	/* Left vertical line line */
	for (y = 0; y < image->height; y++)
		for (x = 0; x < size; x++)
			if (!image_set_pixel(image, x, y, color))
				return false;

	/* Right vertical line line */
	for (y = 0; y < image->height; y++)
		for (x = image->width - size; x < image->width; x++)
			if (!image_set_pixel(image, x, y, color))
				return false;


	return true;
}
