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

    if(elf_rem.dynsym == None):
        print('dynsym table not found in File!')
        sys.exit(1)

    # collect the complementary set of Symbols for given function names
    collection_dynsym = elf_rem.collect_symbols_by_name(elf_rem.dynsym, functions)
    if(elf_rem.symtab != None):
        collection_symtab = elf_rem.collect_symbols_by_name(elf_rem.symtab, elf_rem.get_collection_names(collection_dynsym))

    print('Functions to remove from library dynsym:')
    elf_rem.print_collection_info(collection_dynsym)
    if(elf_rem.symtab != None):
        print('\nFunctions to remove from library symtab:')
        elf_rem.print_collection_info(collection_symtab)
    ans = input("Type 'yes' to delete theses functions: ")

    if(ans == 'yes'):
        elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)
        if(elf_rem.symtab != None):
            # don't override functions again
            elf_rem.remove_from_section(elf_rem.symtab, collection_symtab, False)

if __name__ == '__main__':
    if(len(sys.argv) < 3):
        print('Usage: python3 remove_tool.py <library> <func1> ... <funcN>')
        sys.exit(1)
    proc(sys.argv[1], sys.argv[2:])
