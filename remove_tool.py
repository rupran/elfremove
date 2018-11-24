#!/usr/bin/python3

from elf_remove_class import ELFRemove
import sys

def proc(filename, functions):
    elf_rem = ELFRemove(filename, True)

    if(elf_rem.dynsym == None):
        print('dynsym table not found in File!')
        sys.exit(1)

    # collect the complementary set of Symbols for given function names
    collection_dynsym = elf_rem.collect_symbols(elf_rem.dynsym, functions, True)
    if(elf_rem.symtab != None):
        collection_symtab = elf_rem.collect_symbols(elf_rem.symtab, elf_rem.get_collection_names(collection_dynsym))

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
