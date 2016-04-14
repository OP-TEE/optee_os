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
#include <drivers/frame_buffer.h>

size_t frame_buffer_get_image_size(struct frame_buffer *fb __unused,
			size_t width, size_t height)
{
	return width * height * sizeof(uint32_t);
}

void frame_buffer_clear(struct frame_buffer *fb, uint32_t color)
{
	size_t n;
	uint32_t *base = fb->base;

	for (n = 0; n < fb->width * fb->height; n++)
		base[n] = color;
}

void frame_buffer_set_image(struct frame_buffer *fb, size_t xpos, size_t ypos,
			size_t width, size_t height, const void *image)
{
	size_t x;
	size_t y;
	uint32_t *base = fb->base;
	const uint32_t *img = image;

	for (y = 0; y < height && (y + ypos) < fb->height; y++)
		for (x = 0; x < width && (x + xpos) < fb->width; x++)
			base[x + xpos + (y + ypos) * fb->width] =
				img[x + y * width];
}

