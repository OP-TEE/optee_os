#!/usr/bin/env python3

# Copyright (c) 2019, Ulf Magnusson
# SPDX-License-Identifier: ISC

"""
Writes a configuration file with randomly assigned values for bool/tristate
symbols. Other symbol types keep their defaults.

The default output filename is '.config'. A different filename can be passed
in the KCONFIG_CONFIG environment variable.
"""
import random

import kconfiglib


def main():
    kconf = kconfiglib.standard_kconfig(__doc__)

    # Suppress warnings about setting promptless symbols -- randconfig
    # intentionally assigns values to all symbols regardless.
    kconf.warn = False
    for sym in kconf.unique_defined_syms:
        if sym.type == kconfiglib.BOOL:
            sym.set_value(random.randint(0, 1))
        elif sym.type == kconfiglib.TRISTATE:
            sym.set_value(random.randint(0, 2))
    kconf.warn = True

    print(kconf.write_config())


if __name__ == "__main__":
    main()
