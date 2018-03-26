When OP-TEE encounters a serious error condition, it prints diagnostic
information to the secure console. The message contains a call stack if
``CFG_UNWIND=y`` (enabled by default).

The following errors will trigger a dump:

 - Data or prefetch abort exception in the TEE core (kernel mode) or in a TA
   (user mode),
 - When a user-mode Trusted Application panics, either by calling
   ``TEE_Panic()`` directly or due to some error detected by the TEE Core
   Internal API,
 - When the TEE core detects a fatal error and decides to hang the system
   because there is no way to proceed safely (core panic).

The messages look slightly different depending on:

 - Whether the error is an exception or a panic,
 - The exception/privilege level when the exception occurred (PL0/EL0 if a
   user mode Trusted Application was running, PL1/EL1 if it was the TEE core),
 - Whether the TEE and TA are 32 or 64 bits,
 - The exact type of exception (data or prefetch abort, translation fault,
   read or write permission fault, alignment errors etc).

Here is an example of a panic in a 32-bit Trusted Application, running on a
32-bit TEE core (QEMU)::

 E/TC:0 TA panicked with code 0x0
 E/TC:0 Status of TA 484d4143-2d53-4841-3120-4a6f636b6542 (0xe07ba50) (active)
 E/TC:0  arch: arm  load address: 0x101000  ctx-idr: 1
 E/TC:0  stack: 0x100000 4096
 E/TC:0  region 0: va 0x100000 pa 0xe31d000 size 0x1000 flags rw-
 E/TC:0  region 1: va 0x101000 pa 0xe300000 size 0xf000 flags r-x
 E/TC:0  region 2: va 0x110000 pa 0xe30f000 size 0x3000 flags r--
 E/TC:0  region 3: va 0x113000 pa 0xe312000 size 0xb000 flags rw-
 E/TC:0  region 4: va 0 pa 0 size 0 flags ---
 E/TC:0  region 5: va 0 pa 0 size 0 flags ---
 E/TC:0  region 6: va 0 pa 0 size 0 flags ---
 E/TC:0  region 7: va 0 pa 0 size 0 flags ---
 E/TC:0 Call stack:
 E/TC:0  0x001044a8
 E/TC:0  0x0010ba59
 E/TC:0  0x00101093
 E/TC:0  0x001013ed
 E/TC:0  0x00101545
 E/TC:0  0x0010441b
 E/TC:0  0x00104477
 D/TC:0 user_ta_enter:452 tee_user_ta_enter: TA panicked with code 0x0
 D/TC:0 tee_ta_invoke_command:649 Error: ffff3024 of 3
 D/TC:0 tee_ta_close_session:402 tee_ta_close_session(0xe07be98)
 D/TC:0 tee_ta_close_session:421 Destroy session
 D/TC:0 tee_ta_close_session:447 Destroy TA ctx


The above dump was triggered by the TA when entering an irrecoverable error
ending up in a ``TEE_Panic(0)`` call.

OP-TEE provides a helper script called ``symbolize.py`` to facilitate the
analysis of such issues. It is located in the OP-TEE OS source tree in
``scripts/symbolize.py`` and is also copied to the TA development kit.
Whenever you are confronted with an error message reporting a serious error and
containing a ``"Call stack:"`` line, you may use the symbolize script.

``symbolize.py`` reads its input from ``stdin`` and writes extended debug
information to ``stdout``. The ``-d`` (directories) option tells the script
where to look for TA ELF file(s) (``<uuid>.stripped.elf``) or for ``tee.elf``
(the TEE core). Please refer to ``symbolize.py --help`` for details.

Typical output::

 $ cat dump.txt | ./optee_os/scripts/symbolize.py -d ./optee_examples/*/ta
 # (or run the script, copy and paste the dump, then press Ctrl+D)
 E/TC:0 TA panicked with code 0x0
 E/TC:0 Status of TA 484d4143-2d53-4841-3120-4a6f636b6542 (0xe07ba50) (active)
 E/TC:0  arch: arm  load address: 0x101000  ctx-idr: 1
 E/TC:0  stack: 0x100000 4096
 E/TC:0  region 0: va 0x100000 pa 0xe31d000 size 0x1000 flags rw-
 E/TC:0  region 1: va 0x101000 pa 0xe300000 size 0xf000 flags r-x .ta_head .text .rodata
 E/TC:0  region 2: va 0x110000 pa 0xe30f000 size 0x3000 flags r-- .rodata .ARM.extab .ARM.extab.text.utee_panic .ARM.extab.text.__aeabi_ldivmod .ARM.extab.text.__aeabi_uldivmod .ARM.exidx .got .dynsym .rel.got .dynamic .dynstr .hash .rel.dyn
 E/TC:0  region 3: va 0x113000 pa 0xe312000 size 0xb000 flags rw- .data .bss
 E/TC:0  region 4: va 0 pa 0 size 0 flags ---
 E/TC:0  region 5: va 0 pa 0 size 0 flags ---
 E/TC:0  region 6: va 0 pa 0 size 0 flags ---
 E/TC:0  region 7: va 0 pa 0 size 0 flags ---
 E/TC:0 Call stack:
 E/TC:0  0x001044a8 utee_panic at optee_os/lib/libutee/arch/arm/utee_syscalls_a32.S:74
 E/TC:0  0x0010ba59 TEE_Panic at optee_os/lib/libutee/tee_api_panic.c:35
 E/TC:0  0x00101093 hmac_sha1 at optee_examples/hotp/ta/hotp_ta.c:63
 E/TC:0  0x001013ed get_hotp at optee_examples/hotp/ta/hotp_ta.c:171
 E/TC:0  0x00101545 TA_InvokeCommandEntryPoint at optee_examples/hotp/ta/hotp_ta.c:225
 E/TC:0  0x0010441b entry_invoke_command at optee_os/lib/libutee/arch/arm/user_ta_entry.c:207
 E/TC:0  0x00104477 __utee_entry at optee_os/lib/libutee/arch/arm/user_ta_entry.c:235
 D/TC:0 user_ta_enter:452 tee_user_ta_enter: TA panicked with code 0x0 ???
 D/TC:0 tee_ta_invoke_command:649 Error: ffff3024 of 3
 D/TC:0 tee_ta_close_session:402 tee_ta_close_session(0xe07be98)
 D/TC:0 tee_ta_close_session:421 Destroy session
 D/TC:0 tee_ta_close_session:447 Destroy TA ctx

The Python script uses several tools from the GNU Binutils package to perform
the following tasks:

 1. Translate the call stack addresses into function names, file names and line
    numbers.
 2. Convert the abort address to a symbol plus some offset and/or an ELF section
    name plus some offset.
 3. Print the names of the ELF sections contained in each memory region of a TA.

Note that to successfully run ``symbolize.py`` you must also make your toolchain
visible on the ``PATH`` (i.e., ``export PATH=<my-toolchain-path>/bin:$PATH``).

