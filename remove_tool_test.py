#!/usr/bin/python3

from elf_remove_class import ELFRemove
import sys
import os
import subprocess
import signal
import argparse

from shutil import copyfile

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../librarytrader'))
from librarytrader.librarystore import LibraryStore

parser = argparse.ArgumentParser(description='Removes unneccessary symbols on a copy of given library and tests the given command for SIGSEGV after every symbol removal.')
parser.add_argument('json', help='the json file from libtrader')
parser.add_argument('lib', help='the name of the library')
parser.add_argument('command', nargs=1, help='the command beeing executed with changed library')
parser.add_argument('-v', '--verbosity', action="store_true", help='set verbosity')
parser.add_argument('--args', nargs='*', default=[], help='additional arguments for given command')
parser.add_argument('--chunks', action="store_true",
                    help='test by chunks of of given size (default=10), might speed up the process')
parser.add_argument('--chunksize', default=10, type=int, help='set the chunk size')
parser.add_argument('--all', action="store_true",
                    help='use all librarys from th given json file, lib param is ignored')

def log(mes):
    if(args.verbosity):
        print(mes)

def test_single_func(addr_list, sys_lib_path, lib_copy, elf_rem, blacklist_file):

    # test by single functions in given list
    for single_func in addr_list:
        func = []
        func.append(single_func)

        # collect the set of symbols for given function address
        collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, func)
        if(len(collection_dynsym) == 0):
            log("No function for address \'" + str(single_func) + "\' found!")
            continue
        elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)

        # run command with changed library
        my_env = os.environ.copy()
        my_env["LD_PRELOAD"] = lib_copy
        p1 = subprocess.Popen(args.command + args.args, env=my_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = p1.communicate()

        # print log message
        log("Removed: " + str(single_func) + " " + (collection_dynsym[0][0] if(len(collection_dynsym) > 0) else "not found"))

        # check for sigsegv
        if(p1.returncode == -signal.SIGSEGV):
            log("-----> BROKEN")

            # get new copy of library
            copyfile(sys_lib_path, lib_copy)

            # write to blacklist file
            if os.path.exists(blacklist_file):
                append_write = 'a' # append if already exists
            else:
                append_write = 'w' # make a new file if not
            with open(blacklist_file, append_write) as f:
                f.write(str(single_func) + " " + collection_dynsym[0][0] + "\n")
        else:
            log("-----> OK")

def test_in_chunks(addr, sys_lib_path, lib_copy, elf_rem, blacklist_file):

    # divide in chunks with size given by parameter chunksize
    n = args.chunksize
    lists = [addr[i:i + n] for i in range(0, len(addr), n)]

    for chunk in lists:

        # collect and remove the set of symbols for given function address
        collection_dynsym = elf_rem.collect_symbols_by_address(elf_rem.dynsym, chunk)
        if(len(collection_dynsym) == 0):
            log("No functions for addresses found!")
            log(chunk)
            continue
        elf_rem.remove_from_section(elf_rem.dynsym, collection_dynsym)

        # run given command with preloaded changed library
        my_env = os.environ.copy()
        my_env["LD_PRELOAD"] = lib_copy
        print(args.command + args.args)
        p1 = subprocess.Popen(args.command + args.args, env=my_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.communicate()

        if(args.verbosity):
            log("")
            log("Current Library: " + os.path.basename(sys_lib_path))
            elf_rem.print_collection_info(collection_dynsym)
            print(chunk)

        # check for SIGSEGV
        if(p1.returncode == -signal.SIGSEGV):
            log("-----> SET BROKEN")

            # get new copy of libc
            copyfile(sys_lib_path, lib_copy)

            # if file is broken after removal of chunk -> test every function in chunk indivitual
            test_single_func(chunk, sys_lib_path, lib_copy, elf_rem, blacklist_file)
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
        if(args.all or os.path.basename(lib.fullname) == os.path.basename(args.lib)):
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
            while(True):
                if(os.path.isfile(fname)):
                    fname = fname + "_" + str(iterate)
                    iterate += 1
                else:
                    break

            # find symbols to remove from library
            addr = []
            for key in store[sys_lib_path].exported_addrs.keys():
                value = store[sys_lib_path].export_users[key]
                if not value:
                    addr.append(key)
            if(len(addr) == 0):
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
                test_in_chunks(addr, sys_lib_path, lib_copy, elf_rem, fname)
            else:
                test_single_func(addr, sys_lib_path, lib_copy, elf_rem, fname)

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
