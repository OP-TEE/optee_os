#!/usr/bin/env python
#
# Copyright (c) 2015, Linaro Limited
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

def get_args():
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument('--prefix', required=True, \
		help='Prefix for the public key exponent and modulus in c file')

	parser.add_argument('--out', required=True, \
		help='Name of c file for the public key')

	parser.add_argument('--key', required=True, help='Name of key file')

	return parser.parse_args()

def main():
	import array
	from Crypto.PublicKey import RSA
	from Crypto.Util.number import long_to_bytes

	args = get_args();

	f = open(args.key, 'r')
	key = RSA.importKey(f.read())
	f.close

	f = open(args.out, 'w')

	f.write("#include <stdint.h>\n");
	f.write("#include <stddef.h>\n\n");

	f.write("const uint32_t " + args.prefix + "_exponent = " +
		str(key.publickey().e) + ";\n\n")

	f.write("const uint8_t " + args.prefix + "_modulus[] = {\n")
	i = 0;
	for x in array.array("B", long_to_bytes(key.publickey().n)):
		f.write("0x" + '{0:02x}'.format(x) + ",")
		i = i + 1;
		if i % 8 == 0:
			f.write("\n");
		else:
			f.write(" ");
	f.write("};\n");

	f.write("const size_t " + args.prefix + "_modulus_size = sizeof(" + \
		args.prefix + "_modulus);\n")

	f.close()

if __name__ == "__main__":
	main()
