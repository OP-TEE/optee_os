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


import argparse
import glob
import re
import subprocess
import sys

TA_UUID_RE = re.compile(r'Status of TA (?P<uuid>[0-9a-f\-]+)')
TA_INFO_RE = re.compile(':  arch: (?P<arch>\w+)  '
                        'load address: (?P<load_addr>0x[0-9a-f]+)')
CALL_STACK_RE = re.compile('Call stack:')
STACK_ADDR_RE = re.compile(r':  (?P<addr>0x[0-9a-f]+)')
X64_REGS_RE = re.compile(':  x0  [0-9a-f]{16} x1  [0-9a-f]{16}')

epilog = '''
This scripts reads an OP-TEE abort message from stdin and adds debug
information ('function at file:line') next to each address in the call stack.
It uses the paths provided on the command line to locate the appropriate ELF
binary (tee.elf or Trusted Application) and runs arm-linux-gnueabihf-addr2line
or aarch64-linux-gnu-addr2line to process the addresses.

OP-TEE abort messages are sent to the secure console. They look like the
following:

  ERROR:   TEE-CORE: User TA data-abort at address 0xffffdecd (alignment fault)
  ...
  ERROR:   TEE-CORE: Call stack:
  ERROR:   TEE-CORE:  0x4000549e
  ERROR:   TEE-CORE:  0x40001f4b
  ERROR:   TEE-CORE:  0x4000273f
  ERROR:   TEE-CORE:  0x40005da7

Inspired by a script of the same name by the Chromium project.

Sample usage:

  $ scripts/symbolize.py -d out/arm-plat-hikey/core -d ../optee_test/out/ta/*
  <paste whole dump here>
  ^D
'''

def get_args():
    parser = argparse.ArgumentParser(
                formatter_class=argparse.RawDescriptionHelpFormatter,
                description='Symbolizes OP-TEE abort dumps',
                epilog=epilog)
    parser.add_argument('-d', '--dir', action='append', nargs='+',
        help='Search for ELF file in DIR. tee.elf is needed to decode '
             'a TEE Core or pseudo-TA abort, while <TA_uuid>.elf is required '
             'if a user-mode TA has crashed.')
    parser.add_argument('-s', '--strip_path',
        help='Strip STRIP_PATH from file paths')

    return parser.parse_args()

class Symbolizer(object):
    def __init__(self, out, dirs, strip_path):
        self._out = out
        self._dirs = dirs
        self._strip_path = strip_path
        self._addr2line = None
        self._bin = 'tee.elf'
        self.reset()

    def get_elf(self, elf_or_uuid):
        if not elf_or_uuid.endswith('.elf'):
            elf_or_uuid += '.elf'
        for d in self._dirs:
            elf = glob.glob(d + '/' + elf_or_uuid)
            if elf:
                return elf[0]

    def spawn_addr2line(self):
        if not self._addr2line:
            elf = self.get_elf(self._bin)
            if not elf:
                return
            if self._arch == 'arm':
                cmd = 'arm-linux-gnueabihf-addr2line'
            elif self._arch == 'aarch64':
                cmd = 'aarch64-linux-gnu-addr2line'
            else:
                return
            self._addr2line = subprocess.Popen([cmd, '-f', '-p', '-e', elf],
                                                stdin = subprocess.PIPE,
                                                stdout = subprocess.PIPE)

    def resolve(self, addr):
        offs = self._load_addr
        if int(offs, 0) > int(addr, 0):
            return '???'
        reladdr = '0x{:x}'.format(int(addr, 0) - int(offs, 0))
        self.spawn_addr2line()
        if not self._addr2line:
            return '???'
        try:
            print >> self._addr2line.stdin, reladdr
            ret = self._addr2line.stdout.readline().rstrip('\n')
        except IOError:
            ret = '!!!'
        return ret

    def reset(self):
        self._call_stack_found = False
        self._load_addr = '0'
        if self._addr2line:
            self._addr2line.terminate()
            self._addr2line = None
        self._arch = 'arm'

    def write(self, line):
            if self._call_stack_found:
                match = re.search(STACK_ADDR_RE, line)
                if match:
                    addr = match.group('addr')
                    pre = match.start('addr')
                    post = match.end('addr')
                    self._out.write(line[:pre])
                    self._out.write(addr)
                    res = self.resolve(addr)
                    if self._strip_path:
                        res = re.sub(re.escape(self._strip_path) + '/*', '',
                              res)
                    self._out.write(' ' + res)
                    self._out.write(line[post:])
                    return
                else:
                    self.reset()
            match = re.search(CALL_STACK_RE, line)
            if match:
                self._call_stack_found = True
            match = re.search(TA_UUID_RE, line)
            if match:
                self._bin = match.group('uuid')
            match = re.search(TA_INFO_RE, line)
            if match:
                self._arch = match.group('arch')
                self._load_addr = match.group('load_addr')
            match = re.search(X64_REGS_RE, line)
            if match:
                # Assume _arch represents the TEE core. If we have a TA dump,
                # it will be overwritten later
                self._arch = 'aarch64'
            self._out.write(line)

    def flush(self):
        self._out.flush()

def main():
    args = get_args()
    if args.dir:
        # Flatten list in case -d is used several times *and* with multiple
        # arguments
        args.dirs = [item for sublist in args.dir for item in sublist]
    else:
        args.dirs = []
    symbolizer = Symbolizer(sys.stdout, args.dirs, args.strip_path)

    for line in sys.stdin:
        symbolizer.write(line)
    symbolizer.flush()

if __name__ == "__main__":
    main()
