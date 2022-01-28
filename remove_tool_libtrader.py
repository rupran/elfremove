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
import shutil
import logging
import subprocess
import tempfile
import time
import traceback

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
parser.add_argument('--keep_files', action="store_true", help='generate keep files for shrinkelf')
parser.add_argument('-v', '--verbose', action="store_true", help='set verbosity')
parser.add_argument('--debug', action="store_true", help=argparse.SUPPRESS)

def collect_statistics(lib, elf_rem, parse_time, disas_time, shrink_time, file_size,
                       prev_dynsym_entries, full_set):
    exec_bytes = elf_rem.get_executable_bytes()
    removed_bytes = elf_rem.get_removed_bytes()
    # unique addresses in both dictionaries
    global_dict, local_dict = elf_rem.get_size_dicts()

    unique_globals = len(lib.exported_addrs)
    unique_locals = len(lib.local_functions)

    full_set.add('{},{},{},{},{},{},{},{},{},{},{},{}'.format(lib.fullname,
                                                              prev_dynsym_entries,
                                                              exec_bytes,
                                                              unique_globals,
                                                              unique_locals,
                                                              exec_bytes - removed_bytes,
                                                              unique_globals - len(global_dict),
                                                              unique_locals - len(local_dict),
                                                              parse_time,
                                                              disas_time,
                                                              shrink_time,
                                                              file_size))

def extract_debuginfo(directory, filename, lib):
    debug_filename = os.path.join(directory, lib.fullname.lstrip('/') + '.debug')
    debug_subdirectory = os.path.dirname(debug_filename)
    os.makedirs(os.path.dirname(debug_filename), exist_ok=True)
    logging.debug('* Trying to extract debug information')
    retval = subprocess.run(['strip', '--only-keep-debug', '-o',
                                debug_filename, filename])
    if retval.returncode != 0:
        logging.error(' * Error pulling debug info from %s', filename)
    else:
        logging.debug(' * Debug information now at %s', debug_filename)
        debug_environ = os.environ.get('EXTERNAL_DEBUG_DIR', '')
        paths = [p for p in debug_environ.split(':') if p]
        if debug_subdirectory not in paths:
            if debug_environ:
                debug_environ += ':' + debug_subdirectory
            else:
                debug_environ = debug_subdirectory
        os.environ['EXTERNAL_DEBUG_DIR'] = debug_environ
        logging.debug(' * EXTERNAL_DEBUG_DIR is now set to %s', os.environ['EXTERNAL_DEBUG_DIR'])

def strip_target_file(filename):
    if not args.overwrite:
        logging.debug('* Running \'strip -s %s\'', filename)
        retval = subprocess.run(['strip', '-s', filename])
        if retval.returncode != 0:
            logging.error('  * Error stripping %s!', filename)

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

    debuginfo_tempdir = tempfile.mkdtemp(prefix='elfremove_')

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
            shutil.copy(lib.fullname, filename)
        else:
            print("Library \'" + filename + "\' already exists! Ignoring!")
            continue

        # Strip debug information to a temporary directory
        extract_debuginfo(debuginfo_tempdir, filename, lib)

        # strip debug sections from copied library file
        strip_target_file(filename)

        file_size = os.stat(filename).st_size

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

        before = time.time()
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

        # Store number of dynsym entries before shrinking
        prev_dynsym_entries = (elf_rem.dynsym.section.header['sh_size'] //
                               elf_rem.dynsym.section.header['sh_entsize'])

        # Fix sizes in collection to remove nop-only gaps
        elf_rem.fixup_function_ranges(lib.fullname, lib.ranges)

        # display statistics
        if args.debug:
            elf_rem.print_removed_functions()
        else:
            elf_rem.print_dynsym_info()

        if args.addr_list:
            elf_rem.print_function_addresses()

        # remove symbols from file
        try:
            elf_rem.remove_symbols_from_dynsym()
            if elf_rem.symtab is not None:
                # don't override functions again
                elf_rem.remove_symbols_from_symtab(overwrite=False)

            shrink_time = time.time() - before

            # Generate parameter file for shrinkelf
            if args.keep_files:
                # Write the parameter list to the output file
                with open('keep_file_{}'.format(os.path.basename(filename)), 'w') as fd:
                    for start, end in elf_rem.get_keep_list(file_size):
                        if start != end:
                            fd.write('0x{:x}-0x{:x}\n'.format(start, end))

            collect_statistics(lib, elf_rem, lib.parse_time, lib.total_disas_time,
                               shrink_time, file_size, prev_dynsym_entries, stats_set)
        except Exception as e:
            print("Caught exception!")
            traceback.print_exc()
            if args.overwrite:
                shutil.copy(filename, lib.fullname)
            else:
                os.remove(filename)
            print(e)
            sys.exit(1)
        except KeyboardInterrupt:
            print("Keyboard Interrupt!")
            traceback.print_exc()
            if args.overwrite:
                shutil.copy(filename, lib.fullname)
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

    # TODO: delete temporary symtab files and directory

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
