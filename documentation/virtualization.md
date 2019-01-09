# Virtualization Support #

## Overview ##

OP-TEE have experimental virtualization support. This is when one
OP-TEE instance can run TAs from multiple virtual machines. OP-TEE
isolates all VM-related states, so one VM can't affect another in any
way.

With virtualization support enabled, OP-TEE will rely on a hypervisor,
because only the hypervisor knows which VM is calling OP-TEE. Also,
naturally the hypervisor should inform OP-TEE about creation and
destruction of VMs. Besides, in almost all cases, hypervisor enables
two-stage MMU translation, so VMs does not see real physical address
of memory, instead they work with intermediate physical addresses
(IPAs). On other hand OP-TEE can't translate IPA to PA, so this is a
hypervisor's responsibility to do this kind of translation. So,
hypervisor should include a component that knows about OP-TEE protocol
internals and can do this translation. We call this component "TEE
mediator" and right now only XEN hypervisor have OP-TEE mediator.

## Configuration ##

Virtualization support is enabled with `CFG_VIRTUALIZATION`
configuration option. When this option is enabled, OP-TEE will **not**
work without compatible a hypervisor. This is because the hypervisor
should send `OPTEE_SMC_VM_CREATED` SMC with VM ID before any standard
SMC can be received from client.

`CFG_VIRT_GUEST_COUNT` controls the maximum number of supported
VMs. As OP-TEE have limited size of available memory, increasing this
count will decrease amount of memory available to one VM. Because we
want VMs to be independent, OP-TEE splits available memory in equal
portions to every VM, so one VM can't consume all memory and cause DoS
to other VMs.

## Requirements for hypervisor ##

As said earlier, hypervisor should be aware of OP-TEE and SMCs from
virtual guests to OP-TEE. This is a list of things, that compatible
hypervisor should perform:

1. When new OP-TEE-capable VM is created, hypervisor should inform
   OP-TEE about it with SMC `OPTEE_SMC_VM_CREATED`. `a1` parameter should
   contain VM id. ID 0 is defined as `HYP_CLNT_ID` and is reserved for
   hypervisor itself.

2. When OP-TEE-capable VM is being destroyed, hypervisor should stop
   all VCPUs (this will ensure that OP-TEE have no active threads for
   that VMs) and send SMC `OPTEE_SMC_VM_DESTROYED` with the same
   parameters as for `OPTEE_SMC_VM_CREATED`.

3. Any SMC to OP-TEE should have VM ID in `a7` parameter. This is
   either `HYP_CLNT_ID` if call originates from hypervisor or VM ID
   that was passed in `OPTEE_SMC_VM_CREATED` call.

4. Hypervisor should perform IPA<->PA address translation for all
   SMCs. This includes both arguments in `a1`-`a6` registers and in
   in-memory command buffers.

5. Hypervisor should pin memory pages that VM shares with OP-TEE. This
   means, that hypervisor should ensure that pinned page will reside
   at the original PA as long, as it is shared with OP-TEE. Also it
   should still belong to the VM that shared it. For example, the
   hypervisor should not swap out this page, transfer ownership to
   another VM, unmap it from VM address space and so on.

6. Naturally, the hypervisor should correctly handle the OP-TEE
   protocol, so for any VM it should look like it is working with
   OP-TEE directly.

## Limitations ##

Virtualization support is in experimental state and it have some
limitations, user should be aware of.

### Platforms support ###

Only Armv8 architecture is supported. There is no hard restriction,
but currently Armv7-specific code (like MMU or thread manipulation)
just know nothing about virtualization.

Only one platform has been tested right now and that is QEMU-V8 (aka
qemu that emulates Arm Versatile Express with Armv8 architecture).

Support for Rcar Gen3 should be added soon.

### Static VMs guest count and memory allocation ###

Currently, a user should configure maximum number of guests. OP-TEE will
split memory into equal chunks, so every VM will have the same amount of
memory. For example, if you have 6MB for your TAs, you can set
`CFG_VIRT_GUEST_COUNT` to 3 and every VM would be able to use 2MB
maximum, even if there is no other VMs running.

This is okay for embedded setups when you know exact number and roles
of VMs, but can be inconvenient for server applications.

Also, it is impossible to configure amount of memory available for a
given VM. Every VM instance will have exactly the same amount of memory.

### Sharing hardware resources and PTAs ###

Right now only HW that can be used by multiple VMs simultaneously is
serial console, used for logging. Devices like HW crypto accelerators,
secure storage devices (e.g. external flash storage, accessed directly
from OP-TEE) and others are not supported right now. Drivers
should be made virtualization-aware before they can be used with
virtualization extensions.

Every VM will have own PTA states, which is a good thing in most
cases. But if one wants PTA to have some global state that is shared
between VMs, he need to write PTA accordingly.

### No compatibility with "normal" mode ###

OP-TEE built with `CFG_VIRTUALIZATION=y` will not work without
a hypervisor, because before executing any standard SMC,
`OPTEE_SMC_VM_CREATED` must be called.

This can be inconvenient if one wants to switch between virtualized
and non-virtualized environment frequently. On other hand, it is not a
big deal in a production environment.

Simple workaround can be made for this: if OP-TEE receives standard
SMC prior to `OPTEE_SMC_VM_CREATED`, it implicitly creates VM context
and uses it for all subsequent calls.

## Implementation details ##

OP-TEE as a whole can be split into two entities. Let us call them
"nexus" and TEE. Nexus is a core part of OP-TEE that takes care of low
level things: SMC handling, memory management, threads creation and so
on. TEE is a part that does the actual job: handles requests, loads
TAs, executes them, and so on.

So, it is natural to have one nexus instance and multiple instances of
TEE, one TEE instance per registered VM. This can be done either
explicitly or implicitly.

Explicit way is to move TEE state in some sort of structure and make
all code to access fields of this structure. Something like `struct
task_struct` and `current` in linux kernel. Then it is easy to
allocate such structure for every VM instance. But this approach
basically requires to rewrite all OP-TEE code.

Implicit way is to have banked memory sections for TEE/VM instances.
So memory layout can look something like that:

    +-------------------------------------------------+
    |           Nexus: .nex_bss, .nex_data, ...       |
    +-------------------------------------------------+
    |                   TEE states                    |
    |                                                 |
    | VM1 TEE state | VM 2 TEE state | VM 3 TEE state |
    | .bss, .data   | .bss, .data    | .bss, .data,   |
    +-------------------------------------------------+

This approach requires no changes in TEE code and requires some
changes into nexus code. So, idea that Nexus state resides in separate
sections (`.nex_data`, `.nex_bss`, `.nex_nozi`, `.nex_heap` and
others) and is always mapped.

TEE state resides in standard sections (like `.data`, `.bss`, `.heap`
and so on). There is a separate set of this sections for every VM
registered and Nexus maps them only when it receives call from
corresponding VM.

As Nexus and TEE have separate heaps, `bget` allocator was extended to
work with multiple "contexts". `malloc()`, `free()` with friends work
with one context. `nex_malloc()` (and other `nex_` functions) were
added. They use different context, so now Nexus can use separate heap,
which is always mapped into OP-TEE address space. When virtualization
support is disabled, all those `nex_` functions are defined to point
to standard `malloc()` counterparts.

To change memory mappings in run-time, in MMU code we have added a new
entity, named "partition", which is defined by `struct
mmu_partition`. It holds information about all page-tables, so the whole
MMU mapping can be switched by one write to `TTBR` register.

There is the default partition, it holds MMU state when there is no VM
context active, so no TEE state is mapped. When OP-TEE receives
`OPTEE_SMC_VM_CREATED` call, it copies default partition into new one
and then maps sections with TEE data. This is done by
`prepare_memory_map()` function in `virtualization.c`.

When OP-TEE receives STD call it checks that the supplied VM ID is
valid and then activates corresponding MMU partition, so TEE code can
access its own data. This is basically how virtualization support is
working.
