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
import time

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))

from librarytrader.librarystore import LibraryStore
from elfremove.elfremove import ELFRemove

parser = argparse.ArgumentParser(description='Remove unneccessary symbols of given librarys.')
parser.add_argument('json', help='the json file from libtrader')
parser.add_argument('-l', '--local', action="store_true", help='remove local functions')
parser.add_argument('--lib', nargs='*', help='list of librarys to be processed, use all librarys from json file if not defined')
parser.add_argument('--libonly', action="store_true", help='name of binary has to start with \'lib\'')
parser.add_argument('--overwrite', action="store_true", help='overwrite original library files, otherwise work with a copy in the current working directory')
parser.add_argument('--addr_list', action="store_true", help='print list of removed locations (addresses) with size')
parser.add_argument('-v', '--verbose', action="store_true", help='set verbosity')
parser.add_argument('--debug', action="store_true", help=argparse.SUPPRESS)

def collect_statistics(lib, elf_rem, parse_time, disas_time, shrink_time,
                       collection, local, prev_dynsym_entries, new_path, full_set):
    size_of_text = 0
    for section in elf_rem._elffile.iter_sections():
        if section.name == '.text':
            size_of_text = section["sh_size"]

    # unique addresses in both dictionaries
    global_dict = {}
    local_dict = {}
    for x in collection:
        global_dict[x.value] = max(global_dict.get(x.value, 0), x.size)
    for start, size in local:
        local_dict[start] = max(local_dict.get(start, 0), size)

    addr_dict = global_dict.copy()
    addr_dict.update(local_dict)

    total_b_rem = 0
    for _, v in addr_dict.items():
        total_b_rem += v

    unique_globals = len(lib.exported_addrs)
    unique_locals = len(lib.local_functions)
    filesize = os.path.getsize(lib.fullname)

    full_set.add('{},{},{},{},{},{},{},{},{},{},{},{}'.format(lib.fullname,
                                                              prev_dynsym_entries,
                                                              size_of_text,
                                                              unique_globals,
                                                              unique_locals,
                                                              size_of_text - total_b_rem,
                                                              unique_globals - len(global_dict),
                                                              unique_locals - len(local_dict),
                                                              parse_time,
                                                              disas_time,
                                                              shrink_time,
                                                              filesize))

def proc():

    stats_set = set()
    # get all unused symbol addresses
    store = LibraryStore()
    try:
        store.load(args.json)
    except Exception as e:
        print("Not a valid libtrader json file!")
        print(e)
        sys.exit(1)

    libobjs = store.get_library_objects()

    # create folder for tailored / original librarys
    directory = ""
    if not args.overwrite:
        directory = "./tailored_libs_" + os.path.basename(args.json) + '/'
    else:
        directory = "./original_libs_" + os.path.basename(args.json) + '/'
    if not os.path.exists(directory):
        os.makedirs(directory)

    for lib in libobjs:

        # if no librarys where given -> use all
        if args.lib and os.path.basename(lib.fullname) not in args.lib:
            continue
        if args.libonly and not os.path.basename(lib.fullname).startswith("lib"):
            continue

        filename = directory + lib.fullname

        if not os.path.isdir(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        if not args.overwrite:
            print("\nTailoring library: " + filename)
        else:
            print("\nTailoring library: " + lib.fullname)


        # copy library to folder
        if not os.path.exists(filename):
            copyfile(lib.fullname, filename)
        else:
            print("Library \'" + filename + "\' already exists! Ignoring!")
            continue

        before = time.time()
        # open library file as ELFRemove object
        elf_rem = None
        if args.overwrite:
            ans = input("System library file \'" + lib.fullname + "\' will be changed! Are you sure? (yes):")
            if ans == 'yes':
                elf_rem = ELFRemove(lib.fullname)
            else:
                continue
        else:
            elf_rem = ELFRemove(filename)

        if elf_rem.dynsym is None:
            print('dynsym table not found in File!')
            continue

        # get all blacklistet functions created by test script
        blacklist = []

        blacklist_file = "blacklist_" + os.path.basename(lib.fullname)
        if os.path.exists(blacklist_file):
            print("Found blacklist file for: " + os.path.basename(lib.fullname))
            with open(blacklist_file, "r") as file:
                blacklist_s = file.readlines()
            blacklist = [int(x.strip(), 10) for x in blacklist_s]

        # get all functions to remove from library
        addr = set()
        for key in store[lib.fullname].exported_addrs.keys():
            if key not in blacklist:
                value = store[lib.fullname].export_users[key]
                if not value:
                    addr.add(key)
            else:
                print("In blacklist: " + str(key))

        # collect and remove local functions
        local = set()
        if args.local:
            for key in store[lib.fullname].local_functions.keys():
                if key >= 0xffffffff:
                    continue
                if key not in blacklist:
                    value = store[lib.fullname].local_users.get(key, [])
                    if not value and store[lib.fullname].ranges[key] > 0:
                        local.add((key, store[lib.fullname].ranges[key]))
                else:
                    print("Local in blacklist: " + str(key))

        elf_rem.overwrite_local_functions(local)

        # collect the set of Symbols for given function names
        collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, addr)
        if elf_rem.symtab is not None:
            collection_symtab = elf_rem.collect_symbols_by_name(elf_rem.symtab,
                                                                elf_rem.get_collection_names(collection_dynsym))

        # Fix sizes to remove nop-only gaps
        ranges = store[lib.fullname].ranges
        for symbol in collection_dynsym:
            if symbol.value in ranges and ranges[symbol.value] != symbol.size:
                new_size = ranges[symbol.value]
                logging.debug('fix size for %s:%x: %d->%d', lib.fullname,
                                                            symbol.value,
                                                            symbol.size,
                                                            new_size)
                symbol.size = new_size

        prev_dynsym_entries = (elf_rem.dynsym.section.header['sh_size'] //
                               elf_rem.dynsym.section.header['sh_entsize'])
        # display statistics
        elf_rem.print_collection_info(collection_dynsym, args.debug, local)

        if args.addr_list:
            elf_rem.print_collection_addr(collection_dynsym, local)

        # remove symbols from file
        try:
            elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)
            if elf_rem.symtab is not None:
                # don't override functions again
                elf_rem.remove_from_section(elf_rem.symtab, collection_symtab, False)
            shrink_time = time.time() - before
            collect_statistics(lib, elf_rem, lib.parse_time, lib.total_disas_time,
                               shrink_time, collection_dynsym, local,
                               prev_dynsym_entries, filename, stats_set)
        except Exception as e:
            print("Caught exception!")
            import traceback
            traceback.print_exc()
            if args.overwrite:
                copyfile(filename, lib.fullname)
            else:
                os.remove(filename)
            print(e)
            sys.exit(1)
        except KeyboardInterrupt:
            print("Keyboard Interrupt!")
            import traceback
            traceback.print_exc()
            if args.overwrite:
                copyfile(filename, lib.fullname)
            else:
                os.remove(filename)
            sys.exit(1)

    # filename, dynsym size before, code size before, number of exports before,
    # number of local before, code size after, global functions after,
    # local functions after, time
    with open(directory + 'stats.csv', 'w') as outfd:
        outfd.write('filename,dynsym_entries before,code size before,exported functions before,'\
            'local functions before,code size after,exported functions after,'\
            'local functions after,parse time,disas time,shrink time,filesize before\n')
        for line in sorted(stats_set):
            outfd.write(line)
            outfd.write('\n')


if __name__ == '__main__':
    args = parser.parse_args()
    if args.verbose:
        loglevel = logging.INFO
    elif args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.WARNING
    logging.basicConfig(format='%(asctime)s %(levelname)-7s %(message)s',
                        level=loglevel)
    proc()
