OP-TEE copyright and license headers
====================================

This document deals with the format of the copyright and license headers in
OP-TEE source files. Such headers shall comply with the rules described here.

New source files
----------------

- (Rule 1.1) Shall contain at least one copyright line
- (Rule 1.2) Shall contain at least one SPDX license identifier
- (Rule 1.3) Shall not contain the mention 'All rights reserved' or similar
- (Rule 1.4) Copyrights and license identifiers shall appear in a comment block at
  the first possible line in the file which can contain a comment.
- (Rule 1.5) Files imported from external projects are not new files. The rules for
  pre-existing files (below) apply.

Example:
```
    /*
     * Copyright (c) 2017, Linaro Limited
     * SPDX-License-Identifier: BSD-2-Clause
     */
```

Pre-existing or imported files
------------------------------

- (Rule 2.1) SPDX license identifiers shall be added according to the license
  notice(s) in the file.
  - (Rule 2.1.1) If there is only one license notice, the
    [SPDX](https://spdx.org/licenses/) identifier shall be added into the comment
    block that contains that license, preferably immediately after the copyright
    notice(s). For example:
```
     /*
      * Copyright (c) <year>, <...>
      * SPDX-License-Identifier: <...>
      *
      * <License text>
      */
```
  - (Rule 2.1.2) When a file contains multiple license notices, the SPDX identifiers
    shall be added into their own comment block at the beginning of the
    file, like so:
```
      /*
       * SPDX-License-Identifier: BSD-2-Clause
       * SPDX-License-Identifier: BSD-3-Clause
       */
      /*
       * Copyright (c) <year>, <...>
       *
       * <License text, BSD 2-Clause>
       */
      /*
       * Copyright (c) <year>, <...>
       *
       * <License text, BSD 3-Clause>
       */
```
- (Rule 2.2) It is recommended that license notices be removed once the corresponding
  identifier has been added. This may only be done by the copyright
  holder(s) of the file, however.
- (Rule 2.3) The same recommendation holds for the text: "All rights reserved".
