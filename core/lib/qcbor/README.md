![QCBOR Logo](https://github.com/laurencelundblade/qdv/blob/master/logo.png?raw=true)

**QCBOR** is a powerful, commercial-quality CBOR encoder-decoder that
implements these RFCs:

* [RFC8949](https://tools.ietf.org/html/rfc8949) The CBOR Standard. (Nearly everything
except sorting of encoded maps)
* [RFC7049](https://tools.ietf.org/html/rfc7049) The previous CBOR standard.
Replaced by RFC 8949.
* [RFC8742](https://tools.ietf.org/html/rfc8742) CBOR Sequences
* [RFC8943](https://tools.ietf.org/html/rfc8943) CBOR Dates

## QCBOR Characteristics

**Implemented in C with minimal dependency** – Dependent only
 on C99, <stdint.h>, <stddef.h>, <stdbool.h> and <string.h> making
  it highly portable. <math.h> and <fenv.h> are used too, but their
  use can disabled. No #ifdefs or compiler options need to be set for
  QCBOR to run correctly.

**Focused on C / native data representation** – Careful conversion of
  CBOR data types in to C data types,  handling over and
  underflow, strict typing and such so the caller doesn't have to
  worry so much about this and so code using QCBOR passes static
  analyzers easier.  Simpler code because there is no support for
  encoding/decoding to/from JSON, pretty printing, diagnostic
  notation... Only encoding from native C representations and decoding
  to native C representations is supported.

**Small simple memory model** – Malloc is not needed. The encode
  context is 176 bytes, decode context is 312 bytes and the
  description of decoded data item is 56 bytes. Stack use is light and
  there is no recursion. The caller supplies the memory to hold the
  encoded CBOR and encode/decode contexts so caller has full control
  of memory usage making it good for embedded implementations that
  have to run in small fixed memory.

**Easy decoding of maps** – The "spiffy decode" functions allow
  fetching map items directly by label. Detection of duplicate map
  items is automatically performed. This makes decoding of complex
  protocols much simpler, say when compared to TinyCBOR.

**Supports most of RFC 8949** – With some size limits, all data types
  and formats in the specification are supported. Map sorting is main
  CBOR feature that is not supported.  The same decoding API supports
  both definite and indefinite-length map and array decoding. Decoding
  indefinite length strings is supported but requires a string
  allocator be set up. Encoding of indefinite length strings is
  planned, but not yet supported.

**Extensible and general** – Provides a way to handle data types that
  are not directly supported.

**Secure coding style** – Uses a construct called UsefulBuf as a
  discipline for very safe coding and handling of binary data.

**Small code size** – In the smallest configuration the object
  code is less than 4KB on 64-bit x86 CPUs. The design is such that
  object code for QCBOR APIs not used is not referenced.

**Clear documented public interface** – The public interface is
  separated from the implementation. It can be put to use without
  reading the source.

**Comprehensive test suite** – Easy to verify on a new platform or OS
  with the test suite. The test suite dependencies are minimal and the
  same as the library's.

## Spiffy Decode

These are functions to decode particular data types. They are an
alternative to and built on top of QCBORDecode_GetNext(). They do type
checking and in some cases sophisticated type conversion.

Spiffy decode supports easier map and array decoding. A map can be
descended into with QCBORDecode_EnterMap(). When a map has been
entered, members can be retrieved by label.  Detection of duplicate
map labels, an error, is automatically performed.

An internal error state is maintained. This simplifies the decode
implementation as an error check is only needed at the end of the
decode, rather than on every function.

An outcome is that decoding implementations are simple and involve
many fewer lines of code. They also tend to parallel the encoding
implementations as seen in the following example.

     /* Encode */
     QCBOREncode_Init(&EncodeCtx, Buffer);
     QCBOREncode_OpenMap(&EncodeCtx);
     QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pE->Manufacturer);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pE->uDisplacement);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pE->uHorsePower);
     QCBOREncode_CloseMap(&EncodeCtx);
     uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedEngine);

     /* Decode */
     QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
     QCBORDecode_EnterMap(&DecodeCtx);
     QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
     QCBORDecode_ExitMap(&DecodeCtx);
     uErr = QCBORDecode_Finish(&DecodeCtx);

The spiffy decode functions will handle definite and indefinite length
maps and arrays without the caller having to do anything. This
includes mixed definite and indefinte maps and arrays. (Some work
remains to support map searching with indefinite length strings.)

## Comparison to TinyCBOR

TinyCBOR is a popular widely used implementation. Like QCBOR,
it is a solid, well-maintained commercial quality implementation. This
section is for folks trying to understand the difference in
the approach between QCBOR and TinyCBOR.

TinyCBOR's API is more minimalist and closer to the CBOR
encoding mechanics than QCBOR's. QCBOR's API is at a somewhat higher
level of abstraction.

QCBOR really does implement just about everything described in
RFC 8949. The main part missing is sorting of maps when encoding.
TinyCBOR implements a smaller part of the standard.

No detailed code size comparison has been made, but in a spot check
that encodes and decodes a single integer shows QCBOR about 25%
larger.  QCBOR encoding is actually smaller, but QCBOR decoding is
larger. This includes the code to call the library, which is about the
same for both libraries, and the code linked from the libraries. QCBOR
is a bit more powerful, so you get value for the extra code brought
in, especially when decoding more complex protocols.

QCBOR tracks encoding and decoding errors internally so the caller
doesn't have to check the return code of every call to an encode or
decode function. In many cases the error check is only needed as the
last step or an encode or decode. TinyCBOR requires an error check on
each call.

QCBOR provides a substantial feature that allows searching for data
items in a map by label. It works for integer and text string labels
(and at some point byte-string labels). This includes detection of
items with duplicate labels. This makes the code for decoding CBOR
simpler, similar to the encoding code and easier to read. TinyCBOR
supports search by string, but no integer, nor duplicate detection.

QCBOR provides explicit support many of the registered CBOR tags. For
example, QCBOR supports big numbers and decimal fractions including
their conversion to floats, uint64_t and such.

Generally, QCBOR supports safe conversion of most CBOR number formats
into number formats supported in C. For example, a data item can be
fetched and converted to a C uint64_t whether the input CBOR is an
unsigned 64-bit integer, signed 64-bit integer, floating-point number,
big number, decimal fraction or a big float. The conversion is
performed with full proper error detection of overflow and underflow.

QCBOR has a special feature for decoding byte-string wrapped CBOR. It
treats this similar to entering an array with one item. This is
particularly use for CBOR protocols like COSE that make use of
byte-string wrapping.  The implementation of these protocols is
simpler and uses less memory.

QCBOR's test suite is written in the same portable C that QCBOR is
where TinyCBOR requires Qt for its test. QCBOR's test suite is
designed to be able to run on small embedded devices the same as
QCBOR.

## Code Status

The official current release is version 1.4.1 Changes over the last few
years have been only minor bug fixes, minor feature additions and
documentation improvements. QCBOR 1.x is highly stable.

Work on some larger feature additions is ongoing in "dev" branch.
This includes more explicit support for preferred serialization and
CDE (CBOR Deterministic Encoding).  It will eventually be release as
QCBOR 2.x.

QCBOR was originally developed by Qualcomm. It was [open sourced
through CAF](https://source.codeaurora.org/quic/QCBOR/QCBOR/) with a
permissive Linux license, September 2018 (thanks Qualcomm!).

## Building

There is a simple makefile for the UNIX style command line binary that
compiles everything to run the tests. CMake is also available, please read
the "Building with CMake" section for more information.

These eleven files, the contents of the src and inc directories, make
up the entire implementation.

* inc
   * UsefulBuf.h
   * qcbor_private.h
   * qcbor_common.h
   * qcbor_encode.h
   * qcbor_decode.h
   * qcbor_spiffy_decode.h
* src
   * UsefulBuf.c
   * qcbor_encode.c
   * qcbor_decode.c
   * ieee754.h
   * ieee754.c

For most use cases you should just be able to add them to your
project. Hopefully the easy portability of this implementation makes
this work straight away, whatever your development environment is.

The test directory includes the tests that are nearly as portable as
the main implementation.  If your development environment doesn't
support UNIX style command line and make, you should be able to make a
simple project and add the test files to it.  Then just call
RunTests() to invoke them all.

While this code will run fine without configuration, there are several
C pre processor macros that can be #defined in order to:

 * use a more efficient implementation
 * to reduce code size
 * to improve performance (a little)
 * remove features to reduce code size

See the comment sections on "Configuration" in inc/UsefulBuf.h and
the pre processor defines that start with QCBOR_DISABLE_XXX.

### Building with CMake

CMake can also be used to build QCBOR and the test application. Having the root
`CMakeLists.txt` file, QCBOR can be easily integrated with your project's
existing CMake environment. The result of the build process is a static library,
to build a shared library instead you must add the
`-DBUILD_SHARED_LIBS=ON` option at the CMake configuration step.
The tests can be built into a simple command line application to run them as it
was mentioned before; or it can be built as a library to be integrated with your
development environment.
The `BUILD_QCBOR_TEST` CMake option can be used for building the tests, it can
have three values: `APP`, `LIB` or `OFF` (default, test are not included in the
build).

Building the QCBOR library:

```bash
cd <QCBOR_base_folder>
# Configuring the project and generating a native build system
cmake -S . -B <build_folder>
# Building the project
cmake --build <build_folder>
```

Building and running the QCBOR test app:
```bash
cd <QCBOR_base_folder>
# Configuring the project and generating a native build system
cmake -S . -B <build_folder> -DBUILD_QCBOR_TEST=APP
# Building the project
cmake --build <build_folder>
# Running the test app
.<build_folder>/test/qcbortest
```

To enable all the compiler warnings that are used in the QCBOR release process
you can use the `BUILD_QCBOR_WARN` option at the CMake configuration step:
```bash
cmake -S . -B <build_folder> -DBUILD_QCBOR_WARN=ON
```

### Floating Point Support & Configuration

By default, all QCBOR floating-point features are enabled:

* Encoding and decoding of basic float types, single and double-precision
* Encoding and decoding of half-precision with conversion to/from single
  and double-precision
* Preferred serialization of floating-point
* Floating point dates
* Methods that can convert big numbers, decimal fractions and other numbers
  to/from floating-point

If full floating-point is not needed, the following #defines can be
used to reduce object code size and dependency.

See discussion in qcbor_encode.h for other details.

#### #define QCBOR_DISABLE_FLOAT_HW_USE

This removes dependency on:

* Floating-point hardware and floating-point instructions
* `<math.h>` and `<fenv.h>`
* The math library (libm, -lm)

For most limited environments, this removes enough floating-point
dependencies to be able to compile and run QCBOR.

Note that this does not remove use of the types double and float from
QCBOR, but it limits QCBOR's use of them to converting the encoded
byte stream to them and copying them. Converting and copying them
usually don't require any hardware, libraries or includes. The C
compiler takes care of it on its own.

QCBOR uses its own implementation of half-precision float-pointing
that doesn't depend on math libraries. It uses masks and shifts
instead. Thus, even with this define, half-precision encoding and
decoding works.

When this is defined, the QCBOR functionality lost is minimal and only
for decoding:

* Decoding floating-point format dates are not handled
* There is no conversion between floats and integers when decoding. For
  example, QCBORDecode_GetUInt64ConvertAll() will be unable to convert
  to and from float-point.
* Floats will be unconverted to double when decoding.

No interfaces are disabled or removed with this define.  If input that
requires floating-point conversion or functions are called that
request floating-point conversion, an error code like
`QCBOR_ERR_HW_FLOAT_DISABLED` will be returned.

This saves only a small amount of object code. The primary purpose for
defining this is to remove dependency on floating point hardware and
libraries.

#### #define QCBOR_DISABLE_PREFERRED_FLOAT

This eliminates support for half-precision
and CBOR preferred serialization by disabling
QCBOR's shift and mask based implementation of
half-precision floating-point.

With this defined, single and double-precision floating-point
numbers can still be encoded and decoded. Conversion
of floating-point to and from integers, big numbers and
such is also supported. Floating-point dates are still
supported.

The primary reason to define this is to save object code.
Roughly 900 bytes are saved, though about half of this
can be saved just by not calling any functions that
encode floating-point numbers.

#### #define USEFULBUF_DISABLE_ALL_FLOAT

This eliminates floating point support completely (along with related function
headers). This is useful if the compiler options deny the usage of floating
point operations completely, and the usage soft floating point ABI is not
possible.

#### Compiler options

Compilers support a number of options that control
which float-point related code is generated. For example,
it is usually possible to give options to the compiler to avoid all
floating-point hardware and instructions, to use software
and replacement libraries instead. These are usually
bigger and slower, but these options may still be useful
in getting QCBOR to run in some environments in
combination with `QCBOR_DISABLE_FLOAT_HW_USE`.
In particular, `-mfloat-abi=soft`, disables use of
 hardware instructions for the float and double
 types in C for some architectures.

#### CMake options

If you are using CMake, it can also be used to configure the floating-point
support. These options can be enabled by adding them to the CMake configuration
step and setting their value to 'ON' (True). The following table shows the
available options and the associated #defines.

    | CMake option                      | #define                       |
    |-----------------------------------|-------------------------------|
    | QCBOR_OPT_DISABLE_FLOAT_HW_USE    | QCBOR_DISABLE_FLOAT_HW_USE    |
    | QCBOR_OPT_DISABLE_FLOAT_PREFERRED | QCBOR_DISABLE_PREFERRED_FLOAT |
    | QCBOR_OPT_DISABLE_FLOAT_ALL       | USEFULBUF_DISABLE_ALL_FLOAT   |

## Code Size

These are approximate sizes on a 64-bit x86 CPU with the -Os optimization.
All QCBOR_DISABLE_XXX are set and compiler stack frame checking is disabled
for smallest but not for largest. Smallest is the library functions for a
protocol with strings, integers, arrays, maps and Booleans, but not floats
and standard tag types.

    |               | smallest | largest |
    |---------------|----------|---------|
    | encode only   |      850 |    2200 |
    | decode only   |     1550 |   13300 |
    | combined      |     2500 |   15500 |

 From the table above, one can see that the amount of code pulled in
 from the QCBOR library varies a lot, ranging from 1KB to 15KB.  The
 main factor is the number of QCBOR functions called and
 which ones they are. QCBOR minimizes internal
 interdependency so only code necessary for the called functions is
 brought in.

 Encoding is simpler and smaller. An encode-only implementation may
 bring in only 1KB of code.

 Encoding of floating-point brings in a little more code as does
 encoding of tagged types and encoding of bstr wrapping.

 Basic decoding using QCBORDecode_GetNext() brings in 3KB.

 Use of the supplied MemPool by calling  QCBORDecode_SetMemPool() to
 setup to decode indefinite-length strings adds 0.5KB.

 Basic use of spiffy decode to brings in about 3KB. Using more spiffy
 decode functions, such as those for tagged types bstr wrapping brings
 in more code.

 Finally, use of all of the integer conversion functions will bring in
 about 5KB, though you can use the simpler ones like
 QCBORDecode_GetInt64() without bringing in very much code.

 In addition to using fewer QCBOR functions, the following are some
 ways to make the code smaller.

 The gcc compiler output is usually smaller than llvm because stack
 guards are off by default (be sure you actually have gcc and not llvm
 installed to be invoked by the gcc command). You can also turn off
 stack gaurds with llvm. It is safe to turn off stack gaurds with this
 code because Usefulbuf provides similar defenses and this code was
 carefully written to be defensive.

 If QCBOR is installed as a shared library, then of course only one
 copy of the code is in memory no matter how many applications use it.

### Disabling Features

Here's the list of all features that can be disabled to save object
code. The amount saved is an approximation.

    | #define                                 | Saves |
    | ----------------------------------------| ------|
    | QCBOR_DISABLE_ENCODE_USAGE_GUARDS       |   150 |
    | QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS |   400 |
    | QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS  |   200 |
    | QCBOR_DISABLE_UNCOMMON_TAGS             |   100 |
    | QCBOR_DISABLE_EXP_AND_MANTISSA          |   400 |
    | QCBOR_DISABLE_PREFERRED_FLOAT           |   900 |
    | QCBOR_DISABLE_FLOAT_HW_USE              |    50 |
    | QCBOR_DISABLE_TAGS                      |   400 |
    | QCBOR_DISABLE_NON_INTEGER_LABELS        |   140 |
    | USEFULBUF_DISABLE_ALL_FLOAT             |   950 |

QCBOR_DISABLE_ENCODE_USAGE_GUARDS affects encoding only.  It doesn't
disable any encoding features, just some error checking.  Disable it
when you are confident that an encoding implementation is complete and
correct.

Indefinite lengths are a feature of CBOR that makes encoding simpler
and the decoding more complex. They allow the encoder to not have to
know the length of a string, map or array when they start encoding
it. Their main use is when encoding has to be done on a very
constrained device.  Conversely when decoding on a very constrained
device, it is good to prohibit use of indefinite lengths so the
decoder can be smaller.

The QCBOR decode API processes both definite and indefinite lengths
with the same API, except to decode indefinite-length strings a
storage allocator must be configured.

To reduce the size of the decoder define
QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS particularly if you are not
configuring a storage allocator.

Further reduction can be by defining
QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS which will result in an error
when an indefinite-length map or array arrives for decoding.

QCBOR_DISABLE_UNCOMMON_TAGS disables the decoding of explicit tags for
base 64, regex, UUID and MIME data. This just disables the automatic
recognition of these from a major type 6 tag.

QCBOR_DISABLE_EXP_AND_MANTISSA disables the decoding of decimal
fractions and big floats.

QCBOR_DISABLE_TAGS disables all decoding of CBOR tags. If the input has
a single tag, the error is unrecoverable so it is suitable only for protocols that
have no tags. "Borrowed" tag content formats (e.g. an epoch-based date
without the tag number), can still be processed.

QCBOR_DISABLE_NON_INTEGER_LABELS causes any label that doesn't
fit in an int64_t to result in a QCBOR_ERR_MAP_LABEL_TYPE error.
This also disables QCBOR_DECODE_MODE_MAP_AS_ARRAY and 
QCBOR_DECODE_MODE_MAP_STRINGS_ONLY. It is fairly common for CBOR-based
protocols to use only small integers as labels.

See the discussion above on floating-point.

 ### Size of spiffy decode

 When creating a decode implementation, there is a choice of whether
 or not to use spiffy decode features or to just use
 QCBORDecode_GetNext().

 The implementation using spiffy decode will be simpler resulting in
 the calling code being smaller, but the amount of code brought in
 from the QCBOR library will be larger. Basic use of spiffy decode
 brings in about 2KB of object code.  If object code size is not a
 concern, then it is probably better to use spiffy decode because it
 is less work, there is less complexity and less testing to worry
 about.

 If code size is a concern, then use of QCBORDecode_GetNext() will
 probably result in smaller overall code size for simpler CBOR
 protocols. However, if the CBOR protocol is complex then use of
 spiffy decode may reduce overall code size.  An example of a complex
 protocol is one that involves decoding a lot of maps or maps that
 have many data items in them.  The overall code may be smaller
 because the general purpose spiffy decode map processor is the one
 used for all the maps.


## Other Software Using QCBOR

* [t_cose](https://github.com/laurencelundblade/t_cose) implements enough of
[COSE, RFC 8152](https://tools.ietf.org/html/rfc8152) to support
[CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392) and
[Entity Attestation Token (EAT)](https://tools.ietf.org/html/draft-ietf-rats-eat-06).
Specifically it supports signing and verification of the COSE_Sign1 message.

* [ctoken](https://github.com/laurencelundblade/ctoken) is an implementation of
EAT and CWT.

## Credits
* Ganesh Kanike for porting to QSEE
* Mark Bapst for sponsorship and release as open source by Qualcomm
* Sachin Sharma for release through CAF
* Tamas Ban for porting to TF-M and 32-bit ARM
* Michael Eckel for Makefile improvements
* Jan Jongboom for indefinite length encoding
* Peter Uiterwijk for error strings and other
* Michael Richarson for CI set up and fixing some compiler warnings
* Máté Tóth-Pál for float-point disabling and other
* Dave Thaler for portability to Windows

## Copyright and License

QCBOR is available under what is essentially the 3-Clause BSD License.

Files created inside Qualcomm and open-sourced through CAF (The Code
Aurora Forum) have a slightly modified 3-Clause BSD License. The
modification additionally disclaims NON-INFRINGEMENT.

Files created after release to CAF use the standard 3-Clause BSD
License with no modification. These files have the SPDX license
identifier, "SPDX-License-Identifier: BSD-3-Clause" in them.

### BSD-3-Clause license

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Copyright for this README

Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.
Copyright (c) 2021-2023, Arm Limited. All rights reserved.
