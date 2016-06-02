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

#ifndef __IMAGE_H
#define __IMAGE_H

#include <types_ext.h>

/*
 * Selection of values and names from
 * https://en.wikipedia.org/wiki/X11_color_names
 *
 * The top byte is the alpha channel
 */
#define COLOR_RGB_BLACK			0x00000000
#define COLOR_RGB_BLUE			0x000000FF
#define COLOR_RGB_CYAN			0x0000FFFF
#define COLOR_RGB_DARK_GRAY		0x00A9A9A9
#define COLOR_RGB_DARK_GREEN		0x00006a00
#define COLOR_RGB_DARK_RED		0x008B0000
#define COLOR_RGB_DARK_TURQUOISE	0x008B0000
#define COLOR_RGB_GRAY			0x00BEBEBE
#define COLOR_RGB_GREEN			0x0000FF00
#define COLOR_RGB_LIGHT_GOLDENROD	0x00FAFAD2
#define COLOR_RGB_LIGHT_GRAY		0x00D3D3D3
#define COLOR_RGB_RED			0x00FF0000
#define COLOR_RGB_WHITE			0x00FFFFFF
#define COLOR_RGB_YELLOW		0x00FFFF00

struct image {
	size_t height;
	size_t width;
	void *buf;
	size_t blen;
};

struct image *image_alloc(size_t width, size_t height, uint32_t color);
void image_free(struct image *image);

void *image_get_pixel_ptr(struct image *image, size_t x, size_t y);
bool image_set_pixel(struct image *image, size_t x, size_t y, uint32_t color);
bool image_set_border(struct image *image, size_t size, uint32_t color);

bool image_set_png(struct image *image, size_t x, size_t y, const void *data,
		   size_t data_len);

#endif /*__IMAGE_H*/
