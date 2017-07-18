#!/usr/bin/env python
#
# Copyright (c) 2017, Linaro Limited
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

import sys
import re

def usage():
	print "Usage: {} <section reg exp match> [<skip section>...]".format( \
		sys.argv[0])
	sys.exit (1)

def main():
	if len(sys.argv) < 2 :
		usage()

	in_shdr = False
	section_headers = re.compile("Section Headers:")
	key_to_flags = re.compile("Key to Flags:")
	match_rule = re.compile(sys.argv[1])
	skip_sections = sys.argv[2:]

	for line in sys.stdin:
		if section_headers.match(line) :
			in_shdr = True;
			continue
		if key_to_flags.match(line) :
			in_shdr = False;
			continue

		if not in_shdr :
			continue

		words = line.split()

		if len(words) < 3 :
			continue

		if words[0] == "[" :
			name_offs = 2
		else :
			name_offs = 1;

		sect_name = words[name_offs]
		sect_type = words[name_offs + 1]

		if sect_type != "PROGBITS" :
			continue

		if not match_rule.match(sect_name) :
			continue

		if sect_name in skip_sections :
			continue

		print '\t*({})'.format(sect_name)

if __name__ == "__main__":
        main()
