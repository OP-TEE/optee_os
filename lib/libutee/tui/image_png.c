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

#include <compiler.h>
#include <stdlib.h>
#include <png.h>
#include <tee_api.h>
#include <string.h>
#include <util.h>
#include <utee_defines.h>
#include "image.h"

struct image_work {
	jmp_buf jmpbuf;
	const uint8_t *data;
	const uint8_t *end_data;
};

static void error_cb(png_structp png_ptr, png_const_charp msg __maybe_unused)
{
	struct image_work *w;

	EMSG("%s", msg);

	w = png_get_error_ptr(png_ptr);
	if (!w)
		TEE_Panic(0);
	longjmp(w->jmpbuf, 1);
}

static void warning_cb(png_structp png_ptr __unused,
		       png_const_charp warning_msg __unused)
{
	IMSG("%s", warning_msg);
}

static void read_cb(png_structp png_ptr, png_bytep data, png_size_t length)
{
	struct image_work *w = png_get_io_ptr(png_ptr);

	if (!w)
		png_error(png_ptr, "read_data: w is NULL");

	if ((w->data + length) > w->end_data || (uint8_t *)length > w->end_data)
		png_error(png_ptr, "reached end of file");

	memcpy(data, w->data, length);
	w->data += length;
}

bool image_set_png(struct image *image, size_t x, size_t y, const void *data,
		   size_t data_len)
{
	/* volatile to avoid clobbering when setjmp() returns the second time */
	volatile bool rv = false;
	png_bytep * volatile row_ptrs = NULL;
	png_structp png_ptr;
	png_infop  info_ptr;
	png_byte color_type;
	png_byte bit_depth;
	size_t n;
	size_t width;
	size_t height;
	struct image_work work = {
		.data = data,
		.end_data = (const uint8_t *)data + data_len,
	};

	if (png_sig_cmp(data, 0, data_len))
		return false;

	png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, &work,
					 error_cb, warning_cb);
	if (!png_ptr)
		return false;

	info_ptr = png_create_info_struct(png_ptr);
	if (!info_ptr) {
		png_destroy_read_struct(&png_ptr, NULL, NULL);
		return false;
	}

	if (setjmp(work.jmpbuf))
		goto out;

	png_set_read_fn(png_ptr, &work, read_cb);
	png_read_info(png_ptr, info_ptr);

	width = png_get_image_width(png_ptr, info_ptr);
	height = png_get_image_height(png_ptr, info_ptr);
	color_type = png_get_color_type(png_ptr, info_ptr);
	bit_depth = png_get_bit_depth(png_ptr, info_ptr);

	if ((x + width) > image->width || (y + height) > image->height)
		goto out;

	/*
	 * Read any color_type into 8bit depth, RGBA format.
	 * See http://www.libpng.org/pub/png/libpng-manual.txt
	 */

	if (bit_depth == 16)
		png_set_strip_16(png_ptr);

	if (color_type == PNG_COLOR_TYPE_PALETTE)
		png_set_palette_to_rgb(png_ptr);

	/* PNG_COLOR_TYPE_GRAY_ALPHA is always 8 or 16bit depth. */
	if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
		png_set_expand_gray_1_2_4_to_8(png_ptr);

	if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS))
		png_set_tRNS_to_alpha(png_ptr);

	/* These color_type don't have an alpha channel then fill it with 0 */
	if (color_type == PNG_COLOR_TYPE_RGB ||
	    color_type == PNG_COLOR_TYPE_GRAY ||
	    color_type == PNG_COLOR_TYPE_PALETTE)
		png_set_filler(png_ptr, 0, PNG_FILLER_AFTER);

	if (color_type == PNG_COLOR_TYPE_GRAY ||
	    color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
		png_set_gray_to_rgb(png_ptr);

	png_read_update_info(png_ptr, info_ptr);

	row_ptrs = malloc(sizeof(png_bytep) * height);
	if (!row_ptrs)
		goto out;
	for (n = 0; n < height; n++)
		row_ptrs[n] = image_get_pixel_ptr(image, x, y + n);

	png_read_image(png_ptr, row_ptrs);
	rv = true;
out:
	free(row_ptrs);
	png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
	return rv;
}
