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
import os
import re
import subprocess
import sys

TA_UUID_RE = re.compile(r'Status of TA (?P<uuid>[0-9a-f\-]+)')
TA_INFO_RE = re.compile(':  arch: (?P<arch>\w+)  '
                        'load address: (?P<load_addr>0x[0-9a-f]+)')
CALL_STACK_RE = re.compile('Call stack:')
STACK_ADDR_RE = re.compile(r':  (?P<addr>0x[0-9a-f]+)')
ABORT_ADDR_RE = re.compile('-abort at address (?P<addr>0x[0-9a-f]+)')
REGION_RE = re.compile('region [0-9]+: va (?P<addr>0x[0-9a-f]+) '
                       'pa 0x[0-9a-f]+ size (?P<size>0x[0-9a-f]+)')

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
             'if a user-mode TA has crashed. For convenience, ELF files '
             'may also be given.')
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
            if d.endswith(elf_or_uuid) and os.path.isfile(d):
                return d
            elf = glob.glob(d + '/' + elf_or_uuid)
            if elf:
                return elf[0]

    def set_arch(self):
        if self._arch:
            return
        if self._bin:
            p = subprocess.Popen([ 'file', self.get_elf(self._bin) ],
                                 stdout=subprocess.PIPE)
            output = p.stdout.readlines()
            p.terminate()
            if 'ARM aarch64,' in output[0]:
                self._arch = 'aarch64-linux-gnu-'
            elif 'ARM,' in output[0]:
                self._arch = 'arm-linux-gnueabihf-'

    def arch_prefix(self, cmd):
        self.set_arch()
        return self._arch + cmd

    def spawn_addr2line(self):
        if not self._addr2line:
            elf = self.get_elf(self._bin)
            if not elf:
                return
            cmd = self.arch_prefix('addr2line')
            if not cmd:
                return
            self._addr2line = subprocess.Popen([cmd, '-f', '-p', '-e', elf],
                                                stdin = subprocess.PIPE,
                                                stdout = subprocess.PIPE)

    def subtract_load_addr(self, addr):
        offs = self._load_addr
        if int(offs, 16) > int(addr, 16):
            return ''
        return '0x{:x}'.format(int(addr, 16) - int(offs, 16))

    def resolve(self, addr):
        reladdr = self.subtract_load_addr(addr)
        self.spawn_addr2line()
        if not reladdr or not self._addr2line:
            return '???'
        try:
            print >> self._addr2line.stdin, reladdr
            ret = self._addr2line.stdout.readline().rstrip('\n')
        except IOError:
            ret = '!!!'
        return ret

    def symbol_plus_offset(self, addr):
        ret = ''
        prevsize = 0
        reladdr = self.subtract_load_addr(addr)
        elf = self.get_elf(self._bin)
        cmd = self.arch_prefix('nm')
        if not reladdr or not elf or not cmd:
            return ''
        ireladdr = int(reladdr, 16)
        nm = subprocess.Popen([cmd, '--numeric-sort', '--print-size', elf],
                               stdin = subprocess.PIPE,
                               stdout = subprocess.PIPE)
        for line in iter(nm.stdout.readline, ''):
            try:
                addr, size, _, name = line.split()
            except:
                # Size is missing
                addr, _, name = line.split()
                size = '0'
            iaddr = int(addr, 16)
            isize = int(size, 16)
            if iaddr == ireladdr:
                ret = name
                break
            if iaddr < ireladdr and iaddr + isize >= ireladdr:
                offs = ireladdr - iaddr
                ret = name + '+' + str(offs)
                break
            if iaddr > ireladdr and prevsize == 0:
                offs = iaddr + ireladdr
                ret = prevname + '+' + str(offs)
                break
            prevsize = size
            prevname = name
        nm.terminate()
        return ret

    def section_plus_offset(self, addr):
        ret = ''
        reladdr = self.subtract_load_addr(addr)
        elf = self.get_elf(self._bin)
        cmd = self.arch_prefix('objdump')
        if not reladdr or not elf or not cmd:
            return ''
        iaddr = int(reladdr, 16)
        objdump = subprocess.Popen([cmd, '--section-headers', elf],
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE)
        for line in iter(objdump.stdout.readline, ''):
            try:
                idx, name, size, vma, lma, offs, algn = line.split()
            except:
                continue;
            ivma = int(vma, 16)
            isize = int(size, 16)
            if ivma == iaddr:
                ret = name
                break
            if ivma < iaddr and ivma + isize >= iaddr:
                offs = iaddr - ivma
                ret = name + '+' + str(offs)
                break
        objdump.terminate()
        return ret

    def process_abort(self, line):
        ret = ''
        match = re.search(ABORT_ADDR_RE, line)
        addr = match.group('addr')
        pre = match.start('addr')
        post = match.end('addr')
        sym = self.symbol_plus_offset(addr)
        sec = self.section_plus_offset(addr)
        if sym or sec:
            ret += line[:pre]
            ret += addr
            if sym:
                ret += ' ' + sym
            if sec:
                ret += ' ' + sec
            ret += line[post:]
        return ret

    # Return all ELF sections with the ALLOC flag
    def read_sections(self):
        if self._sections:
            return
        elf = self.get_elf(self._bin)
        cmd = self.arch_prefix('objdump')
        if not elf or not cmd:
            return
        objdump = subprocess.Popen([cmd, '--section-headers', elf],
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE)
        for line in iter(objdump.stdout.readline, ''):
            try:
                _, name, size, vma, _, _, _ = line.split()
            except:
                if 'ALLOC' in line:
                    self._sections.append([name, int(vma, 16), int(size, 16)])

    def overlaps(self, section, addr, size):
        sec_addr = section[1]
        sec_size = section[2]
        if not size or not sec_size:
            return False
        return (addr <= (sec_addr + sec_size - 1)) and ((addr + size - 1) >= sec_addr)

    def sections_in_region(self, addr, size):
        ret = ''
        addr = self.subtract_load_addr(addr)
        if not addr:
            return ''
        iaddr = int(addr, 16)
        isize = int(size, 16)
        self.read_sections()
        for s in self._sections:
            if self.overlaps(s, iaddr, isize):
                ret += ' ' + s[0]
        return ret

    def reset(self):
        self._call_stack_found = False
        self._load_addr = '0'
        if self._addr2line:
            self._addr2line.terminate()
            self._addr2line = None
        self._arch = None
        self._saved_abort_line = ''
        self._sections = []
        self._bin = "tee.elf"

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
            match = re.search(REGION_RE, line)
            if match:
                addr = match.group('addr')
                size = match.group('size')
                self._out.write(line.strip() +
                                self.sections_in_region(addr, size) + '\n');
                return
            match = re.search(CALL_STACK_RE, line)
            if match:
                self._call_stack_found = True
                # Here is a good place to resolve the abort address because we
                # have all the information we need
                if self._saved_abort_line:
                    self._out.write(self.process_abort(self._saved_abort_line))
            match = re.search(TA_UUID_RE, line)
            if match:
                self._bin = match.group('uuid')
            match = re.search(TA_INFO_RE, line)
            if match:
                self._load_addr = match.group('load_addr')
            match = re.search(ABORT_ADDR_RE, line)
            if match:
                self.reset()
                # At this point the arch and TA load address are unknown.
                # Save the line so We can translate the abort address later.
                self._saved_abort_line = line
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
