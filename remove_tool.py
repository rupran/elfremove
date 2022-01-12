#!/usr/bin/python3

# Copyright 2018-2029, Julian Geus <julian.geus@fau.de>
# Copyright 2018-2020, Andreas Ziegler <andreas.ziegler@fau.de>
#
# This file is part of ELFRemove.
#
# ELFRemove is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ELFRemove is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ELFRemove.  If not, see <http://www.gnu.org/licenses/>.

import sys
from elfremove.elfremove import ELFRemove

def proc(filename, functions):
    elf_rem = ELFRemove(filename)

    if elf_rem.dynsym is None:
        print('dynsym table not found in File!')
        sys.exit(1)

    # collect the set of Symbols for given function names
    elf_rem.collect_symbols_in_dynsym(names=functions)
    if elf_rem.symtab is not None:
        elf_rem.collect_symbols_in_symtab(names=elf_rem.get_dynsym_names())

    print('Functions to remove from library dynsym:')
    elf_rem.print_removed_functions()
    if elf_rem.symtab is not None:
        print('\nFunctions to remove from library symtab:')
        elf_rem.print_removed_functions(from_symtab=True)
    ans = input("Type 'yes' to delete theses functions: ")

    if ans == 'yes':
        elf_rem.remove_symbols_from_dynsym()
        if elf_rem.symtab is not None:
            # don't override functions again
            elf_rem.remove_symbols_from_symtab(overwrite=False)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python3 remove_tool.py <library> <func1> ... <funcN>')
        sys.exit(1)
    proc(sys.argv[1], sys.argv[2:])
