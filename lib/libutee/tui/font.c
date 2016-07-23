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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "font.h"
#include "default_bold.h"
#include "default_regular.h"
#include "utf8.h"

#define UCP_CARRIAGE_RETURN	0x000D
#define UCP_TUI_BOLD		0xE000
#define UCP_TUI_UNDERLINE	0xE001
#define UCP_TUI_MOVE_RIGHT	0xE002
#define UCP_TUI_MOVE_DOWN	0xE003

static const struct font *font_regular = &font_default_regular;
static const struct font *font_bold = &font_default_bold;

bool font_set_fonts(const struct font *regular, const struct font *bold)
{
	if (regular->height != bold->height)
		return false;
	font_regular = regular;
	font_bold = bold;
	return true;
}

static const struct font_letter *get_letter(const struct font *font,
			uint32_t cp)
{
	ssize_t idx = cp - font->first;

	if (idx < 0 || cp > font->last)
		return NULL;
	return font->letters + idx;
}

bool font_check_text_format(const char *text, size_t *width, size_t *height,
			size_t *last_idx)
{
	size_t xp = 0;
	size_t xmax = 0;
	size_t ymax = 0;
	size_t idx = 0;
	const struct font *font[2] = { font_regular, font_bold };
	const struct font_letter *letter;
	bool ret = false;
	uint32_t cp;
	bool bold = false;
	size_t font_height = font[0]->height;

	if (!text)
		goto out;

	ymax = font_height;
	while (text[idx]) {
		cp = utf8_get_code_point(text, &idx);
		switch (cp) {
		case UCP_CARRIAGE_RETURN:
			xp = 0;
			ymax += font_height;
			continue;
		case UCP_TUI_BOLD:
			bold = !bold;
			continue;
		case UCP_TUI_UNDERLINE:
			continue;
		case UCP_TUI_MOVE_RIGHT:
			xp++;
			if (xp > xmax)
				xmax = xp;
			continue;
		case UCP_TUI_MOVE_DOWN:
			ymax++;
			continue;
		case UTF8_INVALID_CODE:
			goto out;
		default:
			break;
		}
		if (cp == UTF8_INVALID_CODE)
			goto out;
		letter = get_letter(font[bold], cp);
		if (!letter)
			goto out;
		xp += letter->width;
		if (xp > xmax)
			xmax = xp;
	}
	ret = true;

out:
	if (width)
		*width = xmax + 1;
	if (height)
		*height = ymax + 1;
	if (last_idx)
		*last_idx = idx;
	return ret;
}

size_t font_get_max_field_width(size_t num_letters)
{
	return num_letters * font_regular->max_width;
}

size_t font_get_max_field_length(size_t width)
{
	return width / font_regular->max_width;
}

size_t font_get_text_height(void)
{
	return font_regular->height;
}

static bool letter_get_bit(const struct font_letter *letter, size_t x, size_t y)
{
	const uint8_t *bstr = letter->blob;
	size_t pos = y * ROUNDUP(letter->width, 8) + x;
	size_t byte_pos = pos / 8;
	uint8_t bit_mask = 1 << (7 - (pos & 0x7));

	assert(byte_pos < letter->blob_size);
	return !!(bstr[byte_pos] & bit_mask);
}

static bool render_letter(struct image *image, size_t xpos, size_t ypos,
			const struct font_letter *letter, size_t letter_height,
			uint32_t color)
{
	size_t x;
	size_t y;
	bool res = true;

	for (y = 0; y < letter_height; y++) {
		for (x = 0; x < letter->width; x++) {
			if (letter_get_bit(letter, x, y)) {
				if (!image_set_pixel(image, xpos + x, ypos + y,
						     color))
					res = false;
			}
		}
	}
	return res;
}

bool font_render_text(struct image *image, size_t xpos, size_t ypos,
			const char *text, uint32_t color)
{
	size_t xp = xpos;
	size_t yp = ypos;
	size_t idx = 0;
	const struct font *font[2] = { font_regular, font_bold };
	const struct font_letter *letter;
	bool bold = false;
	bool underline = false;
	uint32_t cp;
	size_t font_height = font[0]->height;

	if (!text)
		return false;

	while (text[idx]) {
		cp = utf8_get_code_point(text, &idx);
		switch (cp) {
		case UCP_CARRIAGE_RETURN:
			xp = xpos;
			yp += font_height;
			continue;
		case UCP_TUI_BOLD:
			bold = !bold;
			continue;
		case UCP_TUI_UNDERLINE:
			underline = !underline;
			continue;
		case UCP_TUI_MOVE_RIGHT:
			xp++;
			continue;
		case UCP_TUI_MOVE_DOWN:
			yp++;
			continue;
		case UTF8_INVALID_CODE:
			return false;
		default:
			break;
		}
		if (cp == UTF8_INVALID_CODE)
			return false;
		letter = get_letter(font[bold], cp);
		if (!letter)
			return false;
		if (!render_letter(image, xp, yp, letter, font_height,
				   color))
			return false;
		if (underline) {
			const struct font_letter *l;
			size_t over_shoot;

			l = get_letter(font[bold], '_');
			if (!l)
				return false;
			if (!render_letter(image, xp, yp, l, font_height,
					   color))
				return false;
			/*
			 * If the letter _ is narrower than the rendered
			 * letter we need to render a second _ to form a
			 * solid line. As the parts of the _ letter
			 * contains some empty space we calculate an
			 * approximate number of pixels to add to
			 * compensate for that.
			 */
			over_shoot = (l->width / 10) + 1;
			if ((l->width - over_shoot) < letter->width) {
				size_t offs = letter->width -
					      (l->width - over_shoot);

				/*
				 * Ignore return value as we may try to
				 * write a part of the underscore outside
				 * the image area. It will not risk
				 * confusing the message in this particular
				 * case as the real text is rendered
				 * properly in either way.
				 */
				render_letter(image, xp + offs, yp, l,
					      font_height, color);
			}
		}
		xp += letter->width;
	}
	return true;
}
