#!/usr/bin/python3

# Copyright 2018-2019, Julian Geus <julian.geus@fau.de>
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
import os
import subprocess
import signal
import argparse

from shutil import copyfile

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))
from librarytrader.librarystore import LibraryStore
from elf_remove_class import ELFRemove

parser = argparse.ArgumentParser(description='Removes unneccessary symbols on a copy of given library and tests the given command for SIGSEGV after every symbol removal.')
parser.add_argument('json', help='the json file from libtrader')
parser.add_argument('command', nargs=1, help='the command beeing executed with changed library')
parser.add_argument('-l', '--local', action="store_true", help='remove local functions')
parser.add_argument('-v', '--verbosity', action="store_true", help='set verbosity')
parser.add_argument('--args', nargs='*', default=[], help='additional arguments for given command')
parser.add_argument('--chunks', action="store_true",
                    help='test by chunks of of given size (default=10), might speed up the process')
parser.add_argument('--chunksize', default=10, type=int, help='set the chunk size')
parser.add_argument('--lib', nargs='*', help='list of librarys to be processed, use all librarys from json file if not defined')

def log(mes):
    if(args.verbosity):
        print(mes)

def test_single_func(addr_list, sys_lib_path, lib_copy, elf_rem, blacklist_file, blacklist, local = False):

    # test by single functions in given list
    for single_func in addr_list:
        address = single_func if (not local) else single_func[0]
        if(address in blacklist):
            log("Address: " + str(address) + " already in blacklist!")
            continue

        func = []
        func.append(single_func)

        collection_dynsym = None
        if(not local):
            # collect the set of symbols for given function address
            collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, func)
            if(len(collection_dynsym) == 0):
                log("No function for address \'" + str(single_func) + "\' found!")
                continue
            elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)
        else:
            elf_rem.overwrite_local_functions(func)

        # run command with changed library
        my_env = os.environ.copy()
        my_env["LD_PRELOAD"] = lib_copy
        p1 = subprocess.Popen(args.command + args.args, env=my_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = p1.communicate()

        # print log message
        if(not local):
            log("Removed: " + str(single_func) + " " + (collection_dynsym[0][0] if(len(collection_dynsym) > 0) else "not found"))
        else:
            log("Removed local: " + str(single_func[0]) + " size: " + str(single_func[1]))

        # check for sigsegv
        if(p1.returncode == -signal.SIGSEGV):
            log("-----> BROKEN")

            # get new copy of library
            copyfile(sys_lib_path, lib_copy)

            # write to blacklist file
            with open(blacklist_file, "a+") as f:
                if(not local):
                    f.write(str(single_func) + '\n')
                else:
                    f.write(str(single_func[0]) + '\n')
        else:
            log("-----> OK")

def test_in_chunks(addr, sys_lib_path, lib_copy, elf_rem, blacklist_file, blacklist, local = False):

    # divide in chunks with size given by parameter chunksize
    n = args.chunksize
    lists = [addr[i:i + n] for i in range(0, len(addr), n)]

    for chunk in lists:

        # collect and remove the set of symbols for given function address
        collection_dynsym = None
        if(not local):
            collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, chunk)
            if(len(collection_dynsym) == 0):
                log("No functions for addresses found!")
                log(chunk)
                continue
            elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)
        else:
            elf_rem.overwrite_local_functions(chunk)

        # run given command with preloaded changed library
        my_env = os.environ.copy()
        my_env["LD_PRELOAD"] = lib_copy
        log("Command: " + str(args.command + args.args))
        p1 = subprocess.Popen(args.command + args.args, env=my_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.communicate()

        if(args.verbosity):
            log("")
            log("Current Library: " + os.path.basename(sys_lib_path))
            if(not local):
                elf_rem.print_collection_info(collection_dynsym)
            else:
                log("Local Functions: ")
            print(chunk)

        # check for SIGSEGV
        if(p1.returncode == -signal.SIGSEGV):
            log("-----> SET BROKEN")

            # get new copy of libc
            copyfile(sys_lib_path, lib_copy)

            # if file is broken after removal of chunk -> test every function in chunk indivitual
            test_single_func(chunk, sys_lib_path, lib_copy, elf_rem, blacklist_file, blacklist, local)
        else:
            log("-----> SET OK")


def proc():

    # load json file as LibraryStore object
    store = LibraryStore()
    store.load(args.json)

    # get all librarys from store object
    libobjs = store.get_library_objects()
    lib_list = []

    # check if library should be tested
    for lib in libobjs:
        if(not args.lib or os.path.basename(lib.fullname) in args.lib):
            print(lib.fullname)
            lib_list.append(lib.fullname)

    # if no librarys found -> die
    if(len(lib_list) == 0):
        if(args.all):
            print("No librarys found in json!")
        else:
            print("Given library: " + args.lib + " not found in json File!")
        sys.exit(1)

    lib_copy = None
    try:
        # test all previously found librarys
        for sys_lib_path in lib_list:
            print("\nTesting library: " + os.path.basename(sys_lib_path))

            # check if blacklist file already exists, if so append version count
            iterate = 1
            fname = "blacklist_" + os.path.basename(sys_lib_path)
            blacklist = []
            if(os.path.exists(fname)):
                ans = input("Blacklist file \'" + fname + "\' already exists. Append new addresses? (yes):")
                if(ans == 'yes'):
                    with open(fname, "r") as file:
                        blacklist_s = file.readlines()
                    blacklist = [int(x.strip(), 10) for x in blacklist_s]
                else:
                    print("Creating new file!")
                    while(True):
                        if(os.path.isfile(fname)):
                            fname = fname + "_" + str(iterate)
                            iterate += 1
                        else:
                            break

            # collect local functions
            local = []
            if(args.local):
                for key in store[sys_lib_path].local_functions.keys():
                    # TODO all keys double -> as string and int, why?
                    if(isinstance(key, str)):
                        continue
                    value = store[sys_lib_path].local_users.get(key, [])
                    if(not value):
                        local.append((key, store[sys_lib_path].ranges[key]))

            # find symbols to remove from library
            addr = []
            for key in store[sys_lib_path].exported_addrs.keys():
                value = store[sys_lib_path].export_users[key]
                if not value:
                    addr.append(key)
            if(len(addr) == 0 and len(local) == 0):
                continue

            # create a library copy in current directory
            lib_copy = "./" + os.path.basename(sys_lib_path)
            if(os.path.isfile(lib_copy)):
                print("File: " + args.lib + " exists in cwd!")
                continue
            copyfile(sys_lib_path, lib_copy)

            # create ELFRemove object for current library
            elf_rem = ELFRemove(lib_copy)
            if(elf_rem.dynsym == None):
                print('dynsym table not found in File!')
                continue

            # remove functions from library
            if(args.chunks):
                if(args.local):
                    test_in_chunks(local, sys_lib_path, lib_copy, elf_rem, fname, blacklist, True)
                test_in_chunks(addr, sys_lib_path, lib_copy, elf_rem, fname, blacklist)
            else:
                if(args.local):
                    test_single_func(local, sys_lib_path, lib_copy, elf_rem, fname, blacklist, True)
                test_single_func(addr, sys_lib_path, lib_copy, elf_rem, fname, blacklist)

            # delete copy of library from cwd
            os.remove(lib_copy)
            lib_copy = None
    except KeyboardInterrupt:
        print("Interrupted by Keyboard!")
        if(lib_copy != None):
            os.remove(lib_copy)
    except Exception as e:
        print("Unexpected Error! " + str(e))
        if(lib_copy != None):
            os.remove(lib_copy)


if __name__ == '__main__':
    args = parser.parse_args()
    proc()
