#!/usr/bin/python3
import sys
import os

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))

from librarytrader.librarystore import LibraryStore
from elf_remove_class import ELFRemove

def proc(filename):
    elf_rem = ELFRemove(filename, True)
    
    if(elf_rem.dynsym == None):
        print('dynsym table not found in File!')
        sys.exit(1)

    # get all unused symbol addresses
    addr = []
    store = LibraryStore()
    store.load("../curl.json")
    for key in store["/usr/lib/i386-linux-gnu/libcurl.so.4.5.0"].exported_addrs.keys():
        value = store["/usr/lib/i386-linux-gnu/libcurl.so.4.5.0"].export_users[key]
        if not value:
            addr.append(key)


    # collect the complementary set of Symbols for given function names
    collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, addr)
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
    if(len(sys.argv) != 2):
        print('Usage: python3 remove_tool_libtrader.py <library>')
        sys.exit(1)
    proc(sys.argv[1])
