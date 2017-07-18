# Benchmark framework
## Contents
1. [Introduction](#1-introduction)
2. [Implementation details](#2-implementation-details)
	* [Design overview](#21-design-overview)
	* [Timestamp source](#22-timestamp-source)
	* [Call sequence diagram](#23-call-sequence-diagram)
3. [Running benchmarks](#3-running-benchmarks)
    * [Benchmark application usage](#31-benchmark-application-usage)
    * [Adding custom timestamps](#32-adding-custom-timestamps)
    * [Analyzing results](#33-analyzing-results)
4. [Limitations and further steps](#4-limitations-and-further-steps)


## 1. Introduction
Due to its nature, OP-TEE is being a solution spanning over several
architectural layers, where each layer includes its own complex parts.
For further optimizations of performance, there is a need of tool which will
provide detailed and precise profiling information for each layer.

It is necessary to receive latency values for:
* The roundtrip time for going from a client application in normal world,
down to a Trusted Application and back again.
* Detailed information for amount of time taken to go through each layer:
	* libTEEC -> Linux OP-TEE kernel driver
	* Linux OP-TEE kernel driver -> OP-TEE OS Core
	* OP-TEE OS Core -> TA entry point (**not supported yet**)
	* The same way back
---
## 2. Implementation details
### 2.1 Design overview

Benchmark framework consists of such components:
1. **Benchmark CA**: a dedicated client application, which is responsible
for allocating timestamp circular buffers, registering these buffers in
the **Benchmark PTA** and consuming all timestamp data generated
by all OP-TEE layers. Finally, it puts timestamp data into appropriate
file with `.ts` extension. Additional details can be found here
here [optee_benchmark]
2. **Benchmark PTA**: pseudo TA, which owns all per-cpu circular non-secure
buffers from a shared memory. **Benchmark PTA** must be invoked (by a CA)
to register the timestamp circular buffers. In turn, the **Benchmark PTA**
invokes the optee linux driver (through some RPC mean) to register this
circular buffers in the linux kernel layer.
3. **libTEEC** and **Linux OP-TEE kernel driver** include functionality for
handling timestamp buffer registration requests from the **Benchmark PTA**.

When benchmark is enabled, all OP-TEE layers (**libTEEC**,
**Linux OP-TEE kernel driver**, **OP-TEE OS Core**) do fill the registered
timestamp circular buffer with timestamp data for all invocation requests on
condition that the circular buffer is allocated/registered.

![design_overview][design_overview]

### 2.2 Timestamp source

ARM Performance Monitor Units are used as the main source of timestamp values.
The reason why this technology was chosen is that it is supported on all
ARMv7/ARMv8 cores. Besides it can provide precise pre-cpu cycle counter values,
it is possible to enable EL0 access to all events, so usermode applications
can directly read cpu counter values from coprocessor registers,
achieving minimal latency by avoiding additional syscalls to EL1 core.

Besides CPU cycle counter values, timestamp by itself contains also
information about:
* Executing CPU core index
* OP-TEE layer id, where this timestamp was
obtained from
* Program counter value when timestamp was logged, which can be used for
getting a symbol name (a filename and line number)

### 2.3 Call sequence diagram

![call_sequence][call_sequence]

---
## 3 Running benchmarks
### 3.1 Benchmark application usage
Before using Benchmark framework, OP-TEE should be rebuild with
`CFG_TEE_BENCHMARK` flag enabled.
```
$ make all CFG_TEE_BENCHMARK=y -j4
```

Then, regular CA and its params should be by-passed to optee_benchmark CA.
```
# benchmark client_app [client_app params]
```

When client_app finishes its execution, optee_benchmark will generate
`<client_app>.ts` timestamp data file in the same directory, where CA is
stored.

### 3.2 Adding custom timestamps
Currently, timestamping is done only for `InvokeCommand` calls, but it's also
possible to choose custom places in the supported OP-TEE layers.

To add timestamp storing command to custom c source file:
1. Include appropriate header:
	* OP-TEE OS Core: `bench.h`
	* Linux OP-TEE kmod: `optee_bench.h`
	* libTEEC: `teec_benchmark.h`
2. Invoke `bm_timestamp()` (for linux kmod use `optee_bm_timestamp()`)
in the function, where you want to put timestamp from.

### 3.3 Analyzing results
Will be added soon

---
## 4. Limitations and further steps
* Implementation of application which will analyze timestamp data and provide
statistics for different types of calls providing avg/min/max values (both CPU
cycles and time values)
* Add support for all platforms, where OP-TEE is supported
* Adding support of S-EL0 timestamping
* Attaching additional payload information to each timestamp, for example,
session
* Timestamping within interrupt context in the OP-TEE OS Core

<!--
To edit benchmark_design diagram use http://draw.io and
benchmark_design.xml source file

For benchmark call sequence diagram use http://mscgen.js.org and
benchmark_sequence.msc source file
-->

[design_overview]: images/benchmark/benchmark_design.png
[call_sequence]: images/benchmark/benchmark_sequence.png
[optee_benchmark]: https://github.com/linaro-swg/optee_benchmark
