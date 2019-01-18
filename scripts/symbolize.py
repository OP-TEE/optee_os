#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017, Linaro Limited
#


import argparse
import glob
import os
import re
import subprocess
import sys

CALL_STACK_RE = re.compile('Call stack:')
# This gets the address from lines looking like this:
# E/TC:0  0x001044a8
STACK_ADDR_RE = re.compile(
    r'[UEIDFM]/T[AC]:( *\?|[0-9]+) +[0-9]* +(?P<addr>0x[0-9a-f]+)')
ABORT_ADDR_RE = re.compile(r'-abort at address (?P<addr>0x[0-9a-f]+)')
REGION_RE = re.compile(r'region [0-9]+: va (?P<addr>0x[0-9a-f]+) '
                       r'pa 0x[0-9a-f]+ size (?P<size>0x[0-9a-f]+)'
                       r'( flags .{6} (\[(?P<elf_idx>[0-9]+)\])?)?')
ELF_LIST_RE = re.compile(r'\[(?P<idx>[0-9]+)\] (?P<uuid>[0-9a-f\-]+)'
                         r' @ (?P<load_addr>0x[0-9a-f\-]+)')

epilog = '''
This scripts reads an OP-TEE abort or panic message from stdin and adds debug
information to the output, such as '<function> at <file>:<line>' next to each
address in the call stack. Any message generated by OP-TEE and containing a
call stack can in principle be processed by this script. This currently
includes aborts and panics from the TEE core as well as from any TA.
The paths provided on the command line are used to locate the appropriate ELF
binary (tee.elf or Trusted Application). The GNU binutils (addr2line, objdump,
nm) are used to extract the debug info. If the CROSS_COMPILE environment
variable is set, it is used as a prefix to the binutils tools. That is, the
script will invoke $(CROSS_COMPILE)addr2line etc. If it is not set however,
the prefix will be determined automatically for each ELF file based on its
architecture (arm-linux-gnueabihf-, aarch64-linux-gnu-). The resulting command
is then expected to be found in the user's PATH.

OP-TEE abort and panic messages are sent to the secure console. They look like
the following:

  E/TC:0 User TA data-abort at address 0xffffdecd (alignment fault)
  ...
  E/TC:0 Call stack:
  E/TC:0  0x4000549e
  E/TC:0  0x40001f4b
  E/TC:0  0x4000273f
  E/TC:0  0x40005da7

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
                        help='Search for ELF file in DIR. tee.elf is needed '
                        'to decode a TEE Core or pseudo-TA abort, while '
                        '<TA_uuid>.elf is required if a user-mode TA has '
                        'crashed. For convenience, ELF files may also be '
                        'given.')
    parser.add_argument('-s', '--strip_path', nargs='?',
                        help='Strip STRIP_PATH from file paths (default: '
                        'current directory, use -s with no argument to show '
                        'full paths)', default=os.getcwd())

    return parser.parse_args()


class Symbolizer(object):
    def __init__(self, out, dirs, strip_path):
        self._out = out
        self._dirs = dirs
        self._strip_path = strip_path
        self._addr2line = None
        self.reset()

    def my_Popen(self, cmd):
        try:
            return subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                print >> sys.stderr, "*** Error:", cmd[0] + \
                    ": command not found"
                sys.exit(1)

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
        self._arch = os.getenv('CROSS_COMPILE')
        if self._arch:
            return
        elf = self.get_elf(self._elfs[0][0])
        if elf is None:
            return
        p = subprocess.Popen(['file', self.get_elf(self._elfs[0][0])],
                             stdout=subprocess.PIPE)
        output = p.stdout.readlines()
        p.terminate()
        if 'ARM aarch64,' in output[0]:
            self._arch = 'aarch64-linux-gnu-'
        elif 'ARM,' in output[0]:
            self._arch = 'arm-linux-gnueabihf-'

    def arch_prefix(self, cmd):
        self.set_arch()
        if self._arch is None:
            return ''
        return self._arch + cmd

    def spawn_addr2line(self, elf_name):
        if elf_name is None:
            return
        if self._addr2line_elf_name is elf_name:
            return
        if self._addr2line:
            self._addr2line.terminate
            self._addr2line = None
        elf = self.get_elf(elf_name)
        if not elf:
            return
        cmd = self.arch_prefix('addr2line')
        if not cmd:
            return
        self._addr2line = self.my_Popen([cmd, '-f', '-p', '-e', elf])
        self._addr2line_elf_name = elf_name

    # If addr falls into a region that maps a TA ELF file, return the load
    # address of that file.
    def elf_load_addr(self, addr):
        if self._regions:
            for r in self._regions:
                r_addr = int(r[0], 16)
                r_size = int(r[1], 16)
                i_addr = int(addr, 16)
                if (i_addr >= r_addr and i_addr < (r_addr + r_size)):
                    # Found region
                    elf_idx = r[2]
                    if elf_idx is not None:
                        return self._elfs[int(elf_idx)][1]
            return None
        else:
            # tee.elf
            return '0x0'

    def elf_for_addr(self, addr):
        l_addr = self.elf_load_addr(addr)
        if l_addr is None:
            return None
        if l_addr is '0x0':
            return 'tee.elf'
        for k in self._elfs:
            e = self._elfs[k]
            if int(e[1], 16) == int(l_addr, 16):
                return e[0]
        return None

    def subtract_load_addr(self, addr):
        l_addr = self.elf_load_addr(addr)
        if l_addr is None:
            return None
        if int(l_addr, 16) > int(addr, 16):
            return ''
        return '0x{:x}'.format(int(addr, 16) - int(l_addr, 16))

    def resolve(self, addr):
        reladdr = self.subtract_load_addr(addr)
        self.spawn_addr2line(self.elf_for_addr(addr))
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
        elf_name = self.elf_for_addr(addr)
        if elf_name is None:
            return ''
        elf = self.get_elf(elf_name)
        cmd = self.arch_prefix('nm')
        if not reladdr or not elf or not cmd:
            return ''
        ireladdr = int(reladdr, 16)
        nm = self.my_Popen([cmd, '--numeric-sort', '--print-size', elf])
        for line in iter(nm.stdout.readline, ''):
            try:
                addr, size, _, name = line.split()
            except ValueError:
                # Size is missing
                try:
                    addr, _, name = line.split()
                    size = '0'
                except ValueError:
                    # E.g., undefined (external) symbols (line = "U symbol")
                    continue
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
        elf_name = self.elf_for_addr(addr)
        if elf_name is None:
            return ''
        elf = self.get_elf(elf_name)
        cmd = self.arch_prefix('objdump')
        if not reladdr or not elf or not cmd:
            return ''
        iaddr = int(reladdr, 16)
        objdump = self.my_Popen([cmd, '--section-headers', elf])
        for line in iter(objdump.stdout.readline, ''):
            try:
                idx, name, size, vma, lma, offs, algn = line.split()
            except ValueError:
                continue
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
    def read_sections(self, elf_name):
        if elf_name is None:
            return
        if elf_name in self._sections:
            return
        elf = self.get_elf(elf_name)
        cmd = self.arch_prefix('objdump')
        if not elf or not cmd:
            return
        self._sections[elf_name] = []
        objdump = self.my_Popen([cmd, '--section-headers', elf])
        for line in iter(objdump.stdout.readline, ''):
            try:
                _, name, size, vma, _, _, _ = line.split()
            except ValueError:
                if 'ALLOC' in line:
                    self._sections[elf_name].append([name, int(vma, 16),
                                                     int(size, 16)])

    def overlaps(self, section, addr, size):
        sec_addr = section[1]
        sec_size = section[2]
        if not size or not sec_size:
            return False
        return ((addr <= (sec_addr + sec_size - 1)) and
                ((addr + size - 1) >= sec_addr))

    def sections_in_region(self, addr, size, elf_idx):
        ret = ''
        addr = self.subtract_load_addr(addr)
        if not addr:
            return ''
        iaddr = int(addr, 16)
        isize = int(size, 16)
        elf = self._elfs[int(elf_idx)][0]
        if elf is None:
            return ''
        self.read_sections(elf)
        if elf not in self._sections:
            return ''
        for s in self._sections[elf]:
            if self.overlaps(s, iaddr, isize):
                ret += ' ' + s[0]
        return ret

    def reset(self):
        self._call_stack_found = False
        if self._addr2line:
            self._addr2line.terminate()
            self._addr2line = None
        self._addr2line_elf_name = None
        self._arch = None
        self._saved_abort_line = ''
        self._sections = {}  # {elf_name: [[name, addr, size], ...], ...}
        self._regions = []   # [[addr, size, elf_idx, saved line], ...]
        self._elfs = {0: ["tee.elf", 0]}  # {idx: [uuid, load_addr], ...}

    def pretty_print_path(self, path):
        if self._strip_path:
            return re.sub(re.escape(self._strip_path) + '/*', '', path)
        return path

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
                res = self.pretty_print_path(res)
                self._out.write(' ' + res)
                self._out.write(line[post:])
                return
            else:
                self.reset()
        match = re.search(REGION_RE, line)
        if match:
            # Region table: save info for later processing once
            # we know which UUID corresponds to which ELF index
            addr = match.group('addr')
            size = match.group('size')
            elf_idx = match.group('elf_idx')
            self._regions.append([addr, size, elf_idx, line])
            return
        match = re.search(ELF_LIST_RE, line)
        if match:
            # ELF list: save info for later. Region table and ELF list
            # will be displayed when the call stack is reached
            i = int(match.group('idx'))
            self._elfs[i] = [match.group('uuid'), match.group('load_addr'),
                             line]
            return
        match = re.search(CALL_STACK_RE, line)
        if match:
            self._call_stack_found = True
            if self._regions:
                for r in self._regions:
                    r_addr = r[0]
                    r_size = r[1]
                    elf_idx = r[2]
                    saved_line = r[3]
                    if elf_idx is None:
                        self._out.write(saved_line)
                    else:
                        self._out.write(saved_line.strip() +
                                        self.sections_in_region(r_addr,
                                                                r_size,
                                                                elf_idx) +
                                        '\n')
            if self._elfs:
                for k in self._elfs:
                    e = self._elfs[k]
                    if (len(e) >= 3):
                        # TA executable or library
                        self._out.write(e[2].strip())
                        elf = self.get_elf(e[0])
                        if elf:
                            rpath = os.path.realpath(elf)
                            path = self.pretty_print_path(rpath)
                            self._out.write(' (' + path + ')')
                        self._out.write('\n')
            # Here is a good place to resolve the abort address because we
            # have all the information we need
            if self._saved_abort_line:
                self._out.write(self.process_abort(self._saved_abort_line))
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
