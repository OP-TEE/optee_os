#!/usr/bin/env python
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from wand.image import Image
from wand.drawing import Drawing
from wand.color import Color
import sys

def get_args():
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('--font_file', required=True, \
			help='Name of font file')
	parser.add_argument('--font_size', type=int, default=40, \
			help='Size of font')
	parser.add_argument('--font_name', required=True, \
			help='Name of font in program')
	parser.add_argument('--out_dir', required=True, \
			help='Out directory')
	parser.add_argument('--verbose', default=False, \
			help='Print informational messages')
	return parser.parse_args()

def c_hex_print(f, str):
	n = 0
	s = ""
	for x in str:
		if n % 8 == 0:
			s += "\t"
		else:
			s += " "
		# Hack to satisfy both Python 2.x and 3.x. In 2.x the variable x
		# is string, while it in Python 3.x it's considered as a class
		# int.
		if sys.version_info > (3, 0):
		    s += "0x%02x," % x
		else:
		    s += "0x%02x," % ord(x)
		n = n + 1
		if n % 8 == 0:
			f.write(s + "\n")
			s = ""
	if n % 8 != 0:
		f.write(s + "\n")
		s = ""

def write_comment(f):
	f.write("/*\n * This file is auto generated with\n")
	f.write(" *")
	for x in sys.argv:
		f.write(" " + x);
	f.write("\n * do not edit.\n */\n")


def main():
	args = get_args()

	draw = Drawing()
	draw.font = args.font_file
	draw.font_size = args.font_size

	font_name = args.font_name
	out_dir = args.out_dir

	img_ref = Image(width=1000, height=1000)

	if args.verbose:
		print("Writing " + out_dir + "/" + font_name + ".c")
	f = open(out_dir + "/" + font_name + ".c", 'w+')
	write_comment(f)
	f.write("#include \"font.h\"\n\n")

	font_height = 0
	range_first = 0x20
	range_last = 0x7d
	font_width = []
	max_width = 0
	for x in range(range_first, range_last + 1):
		letter = chr(x)
		metrics = draw.get_font_metrics(img_ref, letter)
		text_height = int(round(metrics.text_height + 2))
		if font_height == 0:
			font_height = text_height
		assert (font_height == text_height), "font height changed!"
		if max_width == 0:
			max_width = metrics.maximum_horizontal_advance + 2
		assert (max_width == metrics.maximum_horizontal_advance + 2), \
			"font advance width changed!"
		text_width = int(round(metrics.text_width + 2))
		font_width.append(text_width)
		img = Image(width=text_width, height=text_height)
		d = draw.clone()
		d.text(0, int(metrics.ascender), letter)
		d(img)

		img.depth = 1;

		f.write("static const unsigned char ")
		f.write("letter_" + str(hex(x)[2:]) + "[] = {\n")
		c_hex_print(f, img.make_blob(format='A'))
		f.write("};\n\n")
		img.close()

	f.write("static const struct font_letter letters[] = {\n")
	for x in range(range_first, range_last + 1):
		letter_var_name = "letter_" + str(hex(x)[2:])
		f.write("\t{ " + letter_var_name + ", ")
		f.write("sizeof(" + letter_var_name + "), ")
		f.write(str(font_width[x - range_first]) + "},\n")
	f.write("};\n\n")

	f.write("const struct font font_" + font_name + " = {\n")
	f.write("\t.first = " + str(hex(range_first)) + ",\n")
	f.write("\t.last = " + str(hex(range_last)) + ",\n")
	f.write("\t.letters = letters,\n")
	f.write("\t.height = " + str(font_height) + ",\n")
	f.write("\t.max_width = " + str(max_width) + ",\n")
	f.write("};\n")
	f.close()

	if args.verbose:
		print("Writing " + out_dir + "/" + font_name + ".h")
	f = open(out_dir + "/" + font_name + ".h", 'w+')
	write_comment(f)
	f.write("#ifndef __" + font_name.upper() + "_H\n");
	f.write("#define __" + font_name.upper() + "_H\n");
	f.write("#include \"font.h\"\n")
	f.write("extern const struct font font_" + font_name + ";\n")
	f.write("#endif /*__" + font_name.upper() + "_H*/\n");
	f.close()

if __name__ == "__main__":
	main()
