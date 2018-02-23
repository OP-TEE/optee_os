OP-TEE copyright and license headers
====================================

This document defines the format of the copyright and license headers in OP-TEE
source files. Such headers shall comply with the rules described here, which
are compatible with the rules adopted by the Linux kernel community.

New source files
----------------

- (Rule 1.1) Shall contain exactly one SPDX license identifier, which can
  express a single or multiple licenses (refer to SPDX_ for syntax details)
- (Rule 1.2) The SPDX license identifier shall be added as a comment line. It
  shall be the first possible line in the file which can contain a comment.
  The comment style shall depend on the file type:
- (Rule 1.2.1) C source: // SPDX-License-Identifier: <expression>
- (Rule 1.2.2) C header: /* SPDX-License-Identifier: <expression> */
- (Rule 1.2.3) Assembly: /* SPDX-License-Identifier: <expression> */
- (Rule 1.2.4) Python, shell: # SPDX-License-Identifier: <expression>
- (Rule 1.3) Shall contain at least one copyright line
- (Rule 1.4) Shall not contain the mention 'All rights reserved'
- (Rule 1.5) Shall not contain any license notice other than the SPDX license
  identifier

Note that files imported from external projects are not new files. The rules
for pre-existing files (below) apply.

Pre-existing or imported files
------------------------------

- (Rule 2.1) SPDX license identifiers shall be added according to the license
  notice(s) in the file and the rules above (1.1 and 1.2*)
- (Rule 2.2) It is recommended that license notices be removed once the
  corresponding identifier has been added. Note however that this may only be
  done by the copyright holder(s) of the file.
- (Rule 2.3) Similar to 2.2, and subject to the same conditions, the text:
  "All rights reserved" shall be removed also.

.. _SPDX: https://spdx.org/licenses/
