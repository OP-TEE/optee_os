import gdb
import os
from curses.ascii import isgraph

# All paths here have been verified and used with OP-TEE v3.8.0

# OP-TEE binaries
TEE_ELF                  = "optee_os/out/arm/core/tee.elf"

# Trusted applications
# optee_example
AES_TA_ELF               = "out-br/build/optee_examples-1.0/aes/ta/out/5dbac793-f574-4871-8ad3-04331ec17f24.elf"
HELLO_WORLD_TA_ELF       = "out-br/build/optee_examples-1.0/hello_world/ta/out/8aaaf200-2450-11e4-abe2-0002a5d5c51b.elf"
HOTP_TA_ELF              = "out-br/build/optee_examples-1.0/hotp/ta/out/484d4143-2d53-4841-3120-4a6f636b6542.elf"
RANDOM_TA_ELF            = "out-br/build/optee_examples-1.0/random/ta/out/b6c53aba-9669-4668-a7f2-205629d00f86.elf"
ACIPHER_TA_ELF           = "out-br/build/optee_examples-1.0/acipher/ta/out/a734eed9-d6a1-4244-aa50-7c99719e7b7b.elf"
SECURE_STORAGE_TA_ELF    = "out-br/build/optee_examples-1.0/secure_storage/ta/out/f4e750bb-1437-4fbf-8785-8d3580c34994.elf"

# optee_test
RPC_TEST_TA_ELF          = "out-br/build/optee_test-1.0/ta/rpc_test/out/d17f73a0-36ef-11e1-984a-0002a5d5c51b.elf"
SIMS_TA_ELF              = "out-br/build/optee_test-1.0/ta/sims/out/e6a33ed4-562b-463a-bb7e-ff5e15a493c8.elf"
SHA_PERF_TA_ELF          = "out-br/build/optee_test-1.0/ta/sha_perf/out/614789f2-39c0-4ebf-b235-92b32ac107ed.elf"
AES_PERF_TA_ELF          = "out-br/build/optee_test-1.0/ta/aes_perf/out/e626662e-c0e2-485c-b8c8-09fbce6edf3d.elf"
CREATE_FAIL_TEST_TA_ELF  = "out-br/build/optee_test-1.0/ta/create_fail_test/out/c3f6e2c0-3548-11e1-b86c-0800200c9a66.elf"
OS_TEST_LIB_TA_ELF       = "out-br/build/optee_test-1.0/ta/os_test_lib/out/ffd2bded-ab7d-4988-95ee-e4962fff7154.elf"
SOCKET_TA_ELF            = "out-br/build/optee_test-1.0/ta/socket/out/873bcd08-c2c3-11e6-a937-d0bf9c45c61c.elf"
CONCURRENT_TA_ELF        = "out-br/build/optee_test-1.0/ta/concurrent/out/e13010e0-2ae1-11e5-896a-0002a5d5c51b.elf"
SDP_BASIC_TA_ELF         = "out-br/build/optee_test-1.0/ta/sdp_basic/out/12345678-5b69-11e4-9dbb-101f74f00099.elf"
CRYPT_TA_ELF             = "out-br/build/optee_test-1.0/ta/crypt/out/cb3e5ba0-adf1-11e0-998b-0002a5d5c51b.elf"
OS_TEST_TA_ELF           = "out-br/build/optee_test-1.0/ta/os_test/out/5b9e0e40-2636-11e1-ad9e-0002a5d5c51b.elf"
STORAGE_TA_ELF           = "out-br/build/optee_test-1.0/ta/storage/out/b689f2a7-8adf-477a-9f99-32e90c0ad0a2.elf"
STORAGE_BENCHMARK_TA_ELF = "out-br/build/optee_test-1.0/ta/storage_benchmark/out/f157cda0-550c-11e5-a6fa-0002a5d5c51b.elf"
CONCURRENT_LARGE_TA_ELF  = "out-br/build/optee_test-1.0/ta/concurrent_large/out/5ce0c432-0ab0-40e5-a056-782ca0e6aba2.elf"
STORAGE2_TA_ELF          = "out-br/build/optee_test-1.0/ta/storage2/out/731e279e-aafb-4575-a771-38caa6f0cca6.elf"

# Host applications
AES_HOST_ELF             = "out-br/build/optee_examples-1.0/aes/aes"
HELLO_WORLD_HOST_ELF     = "out-br/build/optee_examples-1.0/hello_world/hello_world"
HOTP_HOST_ELF            = "out-br/build/optee_examples-1.0/hotp/hotp"
RANDOM_HOST_ELF          = "out-br/build/optee_examples-1.0/random/random"
ACIPHER_HOST_ELF         = "out-br/build/optee_examples-1.0/acipher/acipher"
SECURE_STORAGE_HOST_ELF  = "out-br/build/optee_examples-1.0/secure_storage/secure_storage"
XTEST_HOST_ELF           = "out-br/build/optee_test-1.0/host/xtest/xtest"

# TF-A binaries
BL1_ELF                  = "arm-trusted-firmware/build/qemu/debug/bl1/bl1.elf"
BL2_ELF                  = "arm-trusted-firmware/build/qemu/debug/bl2/bl2.elf"
BL31_ELF                 = "arm-trusted-firmware/build/qemu/debug/bl31/bl31.elf"

# Linux kernel
LINUX_KERNEL_ELF         = "linux/vmlinux"

# U-Boot
UBOOT_ELF                = "u-boot/u-boot"

# This has been pretty much the same on QEMU v7 for a long time, but it happens
# that it needs to be changed
TA_LOAD_ADDR="0x10d020"

# Main path to a OP-TEE project which can be overridden by exporting
# OPTEE_PROJ_PATH to another valid setup coming from build.git
# (https://github.com/OP-TEE/build)
OPTEE_PROJ_PATH = "/media/jbech/SSHD_LINUX/devel/optee_projects/qemu"
if 'OPTEE_PROJ_PATH' in os.environ:
    OPTEE_PROJ_PATH = os.environ['OPTEE_PROJ_PATH']
    # QEMU v7 is the default, but if OPTEE_PROJ_PATH it's probably QEMU v8 and
    # therefore we take a chance to set the load address for QEMU v8 in case
    # the OPTEE_PROJ_PATH has been changed.
    TA_LOAD_ADDR="0x4000d020"

# The TA_LOAD_ADDR exported as environment variable always has the final
# saying.
if 'TA_LOAD_ADDR' in os.environ:
    TA_LOAD_ADDR = os.environ['TA_LOAD_ADDR']

IS_CONNECTED = False

class Connect(gdb.Command):
    def __init__(self):
        super(Connect, self).__init__("connect", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # Default to the QEMU stub
        remote = "127.0.0.1:1234"
        name = "QEMU gdb stub"

        # For debugging on the remote device
        if arg == "gdbserver":
            remote = "127.0.0.1:12345"
            name = "gdbserver"

        print("Connecting to {} at {}".format(name, remote))
        gdb.execute("target remote {}".format(remote))
        IS_CONNECTED = True

    def complete(self, text, word):
        # Sync the array with invoke
        candidates = ['qemu', 'gdbserver']
        return filter(lambda candidate: candidate.startswith(word), candidates)

Connect()

class LoadOPTEE(gdb.Command):
    def __init__(self):
        super(LoadOPTEE, self).__init__("load_tee", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("Loading TEE core symbols for OP-TEE!")
        gdb.execute("symbol-file {}/{}".format(OPTEE_PROJ_PATH, TEE_ELF))
        gdb.execute("b tee_entry_std")

LoadOPTEE()

class LoadTA(gdb.Command):
    def __init__(self):
        super(LoadTA, self).__init__("load_ta", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            print("Loading symbols for '{}' Trusted Application".format(arg))
            ta = None
            # optee_example
            if arg == "acipher":
                ta = ACIPHER_TA_ELF
            elif arg == "aes":
                ta = AES_TA_ELF
            elif arg == "hello_world":
                ta = HELLO_WORLD_TA_ELF
            elif arg == "hotp":
                ta = HOTP_TA_ELF
            elif arg == "random":
                ta = RANDOM_ELF
            elif arg == "secure_storage":
                ta = SECURE_STORAGE_TA_ELF

            # optee_test
            elif arg == "rpc_test":
                ta = RPC_TEST_TA_ELF
            elif arg == "sims":
                ta = SIMS_TA_ELF
            elif arg == "sha_perf":
                ta = SHA_PERF_TA_ELF
            elif arg == "aes_perf":
                ta = AES_PERF_TA_ELF
            elif arg == "create_fail_test":
                ta = CREATE_FAIL_TEST_TA_ELF
            elif arg == "os_test_lib":
                ta = OS_TEST_LIB_TA_ELF
            elif arg == "socket":
                ta = SOCKET_TA_ELF
            elif arg == "concurrent":
                ta = CONCURRENT_TA_ELF
            elif arg == "sdp_basic":
                ta = SDP_BASIC_TA_ELF
            elif arg == "crypt":
                ta = CRYPT_TA_ELF
            elif arg == "os_test":
                ta = OS_TEST_TA_ELF
            elif arg == "storage":
                ta = STORAGE_TA_ELF
            elif arg == "storage_benchmark":
                ta = STORAGE_BENCHMARK_TA_ELF
            elif arg == "concurrent_large":
                ta = CONCURRENT_LARGE_TA_EL
            elif arg == "storage2":
                ta = STORAGE2_TA_ELF

            else:
                print("Unknown TA!")
                return

            gdb.execute("add-symbol-file {}/{} {}".format(OPTEE_PROJ_PATH, ta, TA_LOAD_ADDR))
            gdb.execute("b TA_InvokeCommandEntryPoint")

        except IndexError:
            print("No TA specified")

    def complete(self, text, word):
        # Sync the array(s) with invoke
        optee_example = ['aes', 'hello_world', 'hotp', 'random', 'acipher', 'secure_storage']
        optee_test = ['rpc_test', 'sims', 'sha_perf', 'aes_perf', 'create_fail_test', 'os_test_lib', 'socket', 'concurrent', 'sdp_basic', 'crypt', 'os_test', 'storage', 'storage_benchmark', 'concurrent_large', 'storage2']
        candidates = optee_example + optee_test
        return filter(lambda candidate: candidate.startswith(word), candidates)

LoadTA()

class LoadHost(gdb.Command):
    def __init__(self):
        super(LoadHost, self).__init__("load_host", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            print("Loading symbols for '{}' Trusted Application".format(arg))
            binary = None
            if arg == "acipher":
                binary = ACIPHER_HOST_ELF
            elif arg == "aes":
                binary = AES_HOST_ELF
            elif arg == "hello_world":
                binary = HELLO_WORLD_HOST_ELF
            elif arg == "hotp":
                binary = HOTP_HOST_ELF
            elif arg == "random":
                binary = RANDOM_HOST_ELF
            elif arg == "secure_storage":
                binary = SECURE_STORAGE_HOST_ELF
            elif arg == "xtest":
                binary = XTEST_HOST_ELF
            else:
                print("Unknown host binary!")
                return
            gdb.execute("symbol-file {}/{}".format(OPTEE_PROJ_PATH, binary))

            # FIXME: This must be updated to support QEMU v8 for example (path ...)
            gdb.execute("set sysroot {}/{}".format(OPTEE_PROJ_PATH, "out-br/host/arm-buildroot-linux-gnueabihf/sysroot"))
            gdb.execute("b main")

        except IndexError:
            print("No host binary specified")

    def complete(self, text, word):
        # Sync the array with invoke
        candidates = ['hello_world', 'hotp', 'random', 'acipher', 'secure_storage', 'xtest']
        return filter(lambda candidate: candidate.startswith(word), candidates)

LoadHost()

class LoadTFA(gdb.Command):
    def __init__(self):
        super(LoadTFA, self).__init__("load_tfa", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            print("Loading symbols for Trusted Firmware A from '{}'".format(arg))
            binary = None
            if arg == "bl1":
                binary = BL1_ELF
            elif arg == "bl2":
                binary = BL2_ELF
            elif arg == "bl31":
                binary = BL31_ELF
            else:
                print("Unknown/unspecified TF-A binary!")
                return
            gdb.execute("symbol-file {}/{}".format(OPTEE_PROJ_PATH, binary))

            if binary == BL1_ELF:
                gdb.execute("b bl1_entrypoint")
                gdb.execute("b bl1_main")
            elif binary == BL2_ELF:
                gdb.execute("b bl2_entrypoint")
                gdb.execute("b bl2_main")
            elif binary == BL31_ELF:
                gdb.execute("b bl31_entrypoint")
                gdb.execute("b bl31_main")
                gdb.execute("b opteed_setup")
                gdb.execute("b opteed_init")
                gdb.execute("b opteed_smc_handler")

        except IndexError:
            print("No TF-A binary specified")

    def complete(self, text, word):
        # Sync the array with invoke
        candidates = ['bl1', 'bl2', 'bl31']
        return filter(lambda candidate: candidate.startswith(word), candidates)

LoadTFA()

class LoadLinux(gdb.Command):
    def __init__(self):
        super(LoadLinux, self).__init__("load_linux", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("Loading symbols for Linux kernel")
        gdb.execute("symbol-file {}/{}".format(OPTEE_PROJ_PATH, LINUX_KERNEL_ELF))
        gdb.execute("b tee_init")
        gdb.execute("b optee_do_call_with_arg")
        gdb.execute("b optee_probe")

LoadLinux()

class LoadUBoot(gdb.Command):
    def __init__(self):
        super(LoadUBoot, self).__init__("load_uboot", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("Loading symbols for U-Boot")
        gdb.execute("symbol-file {}/{}".format(OPTEE_PROJ_PATH, UBOOT_ELF))
        gdb.execute("b _main")

LoadUBoot()

class OPTEECmd(gdb.Command):
    def __init__(self):
        super(OPTEECmd, self).__init__("optee-stat", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if arg == "memlayout":
            CFG_SHMEM_START = gdb.parse_and_eval("CFG_SHMEM_START")
            CFG_SHMEM_SIZE = gdb.parse_and_eval("CFG_SHMEM_SIZE")
            print("SHMEM:  0x{:08x} - 0x{:08x}   size: 0x{:08x} [{:d}]".format(
                int(str(CFG_SHMEM_START), 16),
                int(str(CFG_SHMEM_START + CFG_SHMEM_SIZE), 16),
                int(str(CFG_SHMEM_SIZE), 16),
                int(CFG_SHMEM_SIZE)))

            CFG_TZDRAM_START = gdb.parse_and_eval("CFG_TZDRAM_START")
            CFG_TZDRAM_SIZE = gdb.parse_and_eval("CFG_TZDRAM_SIZE")
            print("TZDRAM: 0x{:08x} - 0x{:08x}   size: 0x{:08x} [{:d}]".format(
                int(str(CFG_TZDRAM_START), 16),
                int(str(CFG_TZDRAM_START + CFG_TZDRAM_SIZE), 16),
                int(str(CFG_TZDRAM_SIZE), 16),
                int(CFG_TZDRAM_SIZE)))

            CFG_TEE_RAM_VA_SIZE = gdb.parse_and_eval("CFG_TEE_RAM_VA_SIZE")
            print("TEE_RAM_VA_SIZE: {} [{:d}]".format(
                CFG_TEE_RAM_VA_SIZE,
                int(CFG_TEE_RAM_VA_SIZE)))

    def complete(self, text, word):
        # Sync the array with invoke
        candidates = ['memlayout']
        return filter(lambda candidate: candidate.startswith(word), candidates)

OPTEECmd()
