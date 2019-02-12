#!/usr/bin/python3
import sys
import os
import argparse
from shutil import copyfile

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))

from librarytrader.librarystore import LibraryStore
from elf_remove_class import ELFRemove

parser = argparse.ArgumentParser(description='Remove unneccessary symbols of given librarys.')
parser.add_argument('json', help='the json file from libtrader')
parser.add_argument('--lib', nargs='*', help='list of librarys to be processed, use all librarys from json file if not defined')
parser.add_argument('--overwrite', action="store_true", help='overwrite original library files, otherwise work with a copy in the current working directory')
parser.add_argument('-v', '--verbose', action="store_true", help='set verbosity')

def log(mes):
    if(args.verbose):
        print(mes)

def proc():

    # get all unused symbol addresses
    store = LibraryStore()
    try:
        store.load(args.json)
    except Exception as e:
        print("Not a valid LibraryStore json file!")
        print(e)
        sys.exit(1)

    libobjs = store.get_library_objects()

    # create folder for tailored / original librarys
    directory = ""
    if(not args.overwrite):
        directory = "./tailored_libs_" + os.path.basename(args.json)
    else:
        directory = "./original_libs_" + os.path.basename(args.json)
    if not os.path.exists(directory):
        os.makedirs(directory)

    for lib in libobjs:

        # if no librarys where given -> use all
        if(args.lib and os.path.basename(lib.fullname) not in args.lib):
            continue

        if(not args.overwrite):
            print("\nTailoring library: " + directory + "/" + os.path.basename(lib.fullname))
        else:
            print("\nTailoring library: " + lib.fullname)

        filename = directory + '/' + os.path.basename(lib.fullname)

        # copy library to folder
        if(not os.path.exists(filename)):
            copyfile(lib.fullname, filename)
        else:
            print("Library \'" + filename + "\' already exists! Ignoring!")
            continue

        # open library file as ELFRemove object
        elf_rem = None
        if(args.overwrite):
            ans = input("System library file \'" + lib.fullname + "\' will be changed! Are you sure? (yes):")
            if(ans == 'yes'):
                elf_rem = ELFRemove(lib.fullname, False)
            else:
                continue
        else:
            elf_rem = ELFRemove(filename, False)

        if(elf_rem.dynsym == None):
            print('dynsym table not found in File!')
            continue

        # get all blacklistet functions created by test script
        blacklist_s = []
        blacklist = []

        blacklist_file = "blacklist_" + os.path.basename(lib.fullname)
        if(os.path.exists(blacklist_file)):
            log("Found blacklist file for: " + os.path.basename(lib.fullname))
            with open("blacklist", "r") as file:
                blacklist_s = file.readlines()
            blacklist = [int(x.strip(), 10) for x in blacklist_s]

        # get all functions to remove from library
        addr = []
        for key in store[lib.fullname].exported_addrs.keys():
            if(key not in blacklist):
                value = store[lib.fullname].export_users[key]
                if(not value):
                    addr.append(key)

        # collect the set of Symbols for given function names
        collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, addr)
        if(elf_rem.symtab != None):
            collection_symtab = elf_rem.collect_symbols_by_name(elf_rem.symtab, elf_rem.get_collection_names(collection_dynsym))

        # display statistics
        if(not args.verbose):
            elf_rem.print_collection_info(collection_dynsym, False)
        else:
            elf_rem.print_collection_info(collection_dynsym, True)

        # remove symbols from file
        try:
            elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)
            if(elf_rem.symtab != None):
                # don't override functions again
                elf_rem.remove_from_section(elf_rem.symtab, collection_symtab, False)
        except Exception as e:
            print("Caught exception!")
            if(args.overwrite):
                copyfile(filename, lib.fullname)
            else:
                os.remove(filename)
            print(e)
            sys.exit(1)
        except KeyboardInterrupt:
            print("Keyboard Interrupt!")
            if(args.overwrite):
                copyfile(filename, lib.fullname)
            else:
                os.remove(filename)
            sys.exit(1)


if __name__ == '__main__':
    args = parser.parse_args()
    proc()
