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
import struct

def main():
    with open ("../out/arm/core/tee.bin", "rb") as f:
        data = f.read(4)
        magic = struct.unpack('<I', data)
        print("Magic: \t\t0x%08x" % magic)

        data = f.read(1)
        version = struct.unpack('<B', data)
        print("Version: \t0x%02x" % version)

        data = f.read(1)
        arch_id = struct.unpack('<B', data)
        print("ArchID: \t0x%02x" % arch_id)

        data = f.read(2)
        flags = struct.unpack('<H', data)
        print("Arch Flags: \t0x%04x" % arch_id)

        data = f.read(4)
        init_size = struct.unpack('<I', data)
        print("Init size: \t0x%04x" % init_size)

        data = f.read(4)
        laddr_h = struct.unpack('<I', data)
        print("Load addr high:\t0x%04x" % laddr_h)

        data = f.read(4)
        laddr_l = struct.unpack('<I', data)
        print("Load addr low: \t0x%04x" % laddr_l)

        data = f.read(4)
        mem_usage = struct.unpack('<I', data)
        print("Mem usage: \t0x%04x" % mem_usage)

        data = f.read(4)
        pgd_size = struct.unpack('<I', data)
        print("Pages size: \t0x%04x" % pgd_size)

if __name__ == "__main__":
        main()
