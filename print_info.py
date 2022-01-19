#!/usr/bin/python3

# Copyright 2018-2019, Julian Geus <julian.geus@fau.de>
# Copyright 2018-2021, Andreas Ziegler <andreas.ziegler@fau.de>
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
import os
import argparse
from shutil import copyfile
import logging

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))

from librarytrader.librarystore import LibraryStore
from elfremove.elfremove import ELFRemove

parser = argparse.ArgumentParser(description='Remove unneccessary symbols of given librarys.')
parser.add_argument('json', help='the json file from libtrader')
parser.add_argument('-l', '--local', action="store_true", help='remove local functions')
parser.add_argument('--lib', nargs='*', help='list of librarys to be processed, use all librarys from json file if not defined')
parser.add_argument('--libonly', action="store_true", help='name of binary has to start with \'lib\'')
parser.add_argument('--addr_list', action="store_true", help='print list of removed locations (addresses) with size')
parser.add_argument('--func_list', action="store_true", help='print list of functions')
parser.add_argument('--keep_files', action="store_true", help='generate keep files for shrinkelf')
parser.add_argument('--debug', action="store_true", help=argparse.SUPPRESS)

def read_blacklist(lib):
    blacklist = []

    blacklist_file = "blacklist_" + os.path.basename(lib.fullname)
    if os.path.exists(blacklist_file):
        print("Found blacklist file for: " + os.path.basename(lib.fullname))
        with open(blacklist_file, "r") as file:
            blacklist_s = file.readlines()
        blacklist = [int(x.strip(), 10) for x in blacklist_s]
    return blacklist

def collect_exported_addrs(lib, blacklist):
    addr = set()
    for key in lib.exported_addrs.keys():
        if key not in blacklist:
            value = lib.export_users[key]
            if not value:
                addr.add(key)
        else:
            print("In blacklist: " + str(key))
    return addr

def collect_local_addrs(lib, blacklist):
    local = set()
    if args.local:
        for key in lib.local_functions.keys():
            if key >= 0xffffffff:
                continue
            if key not in blacklist:
                value = lib.local_users.get(key, [])
                if not value and lib.ranges[key] > 0:
                    local.add((key, lib.ranges[key]))
            else:
                print("Local in blacklist: " + str(key))
    return local

def proc():

    # get all unused symbol addresses
    store = LibraryStore()
    try:
        store.load(args.json)
    except Exception as e:
        print("Not a valid libtrader json file!")
        print(e)
        sys.exit(1)

    libobjs = store.get_library_objects()

    directory = "./tailored_libs_" + os.path.basename(args.json) + '/'
    if not os.path.exists(directory):
        logging.error('output directory does not exist, exiting...')
        sys.exit(1)

    for lib in sorted(libobjs, key=lambda x: x.fullname):

        # if no librarys where given -> use all
        if args.lib and os.path.basename(lib.fullname) not in args.lib:
            continue
        if args.libonly and not os.path.basename(lib.fullname).startswith("lib"):
            continue

        print("\nLibrary: " + lib.fullname)

        filename = lib.fullname
        tailored_filename = directory + lib.fullname

        # open library file as ELFRemove object
        elf_rem = None
        try:
            elf_rem = ELFRemove(filename, open_mode='rb')
        except:
            continue

        if elf_rem.dynsym is None:
            print('dynsym table not found in File!')
            continue

        # get all blacklisted functions created by test script
        blacklist = read_blacklist(lib)

        # get all functions to remove from library
        addr = collect_exported_addrs(lib, blacklist)

        # collect and remove local functions
        elf_rem.local_functions = collect_local_addrs(lib, blacklist)
        elf_rem.overwrite_local_functions()

        # collect the set of Symbols for given function addresses
        elf_rem.collect_symbols_in_dynsym(addrs=addr)
        if elf_rem.symtab is not None:
            elf_rem.collect_symbols_in_symtab(names=elf_rem.get_dynsym_names())

        # Fix sizes in collection to remove nop-only gaps
        elf_rem.fixup_function_ranges(lib.fullname, lib.ranges)

        # display statistics
        if args.keep_files:
            total_size = os.stat(tailored_filename).st_size
            # Write the parameter list to the output file
            with open('keep_file_{}'.format(os.path.basename(filename)), 'w') as fd:
                for start, end in elf_rem.get_keep_list(total_size):
                    if start != end:
                        fd.write('0x{:x}-0x{:x}\n'.format(start, end))

        elif args.addr_list:
            elf_rem.print_function_addresses()
        elif args.func_list:
            elf_rem.print_removed_functions()
        else:
            elf_rem.print_dynsym_info()

if __name__ == '__main__':
    args = parser.parse_args()
    if args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.WARNING
    logging.basicConfig(level=loglevel)

    proc()
