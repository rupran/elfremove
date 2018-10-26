from __future__ import print_function
import sys
import binascii

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.elf.sections import NullSection
from elftools.elf.sections import StringTableSection
from elftools.elf.sections import SymbolTableSection

def error_message(message):
    print('Something went wrong! ', message)
    exit()

def gnuhash(func_name):
    h = 5381
    for c in func_name:
        h = (h << 5) + h + ord(c)
        h = h & 0xFFFFFFFF
    return h

def edit_gnu_hashtable(func_name, elffile, f, dynsym_nr, total_ent_sym):
    # TODO 32-Bit
    ### Find Gnu-Hash Section ###
    # TODO search section only once in main!
    for sect in elffile.iter_sections():
        if sect.name == '.gnu.hash':
            print('Found section at: ', sect.header['sh_offset'])
            f.seek(sect.header['sh_offset'])
            nbuckets_b = f.read(4)
            symoffset_b = f.read(4)
            bloomsize_b = f.read(4)
            bloomshift_b = f.read(4)

            nbuckets = int.from_bytes(nbuckets_b, sys.byteorder, signed=False)
            symoffset = int.from_bytes(symoffset_b, sys.byteorder, signed=False)
            bloomsize = int.from_bytes(bloomsize_b, sys.byteorder, signed=False)
            bloomshift = int.from_bytes(bloomshift_b, sys.byteorder, signed=False)

            bloom_hex = f.read(bloomsize * 8)
            print("Buckets:", nbuckets, symoffset, bloomsize, bloomshift, bloom_hex)

            ### calculate hash and bucket ###
            func_hash = gnuhash(func_name)
            bucket_nr = func_hash % nbuckets
            print("Func: ", func_name, 'Hash:', hex(func_hash), 'Bucket:', bucket_nr)

            bucket_offset = sect.header['sh_offset'] + 4 * 4 + bloomsize * 8

            ### Set new Bucket start values ###
            for cur_bucket in range(bucket_nr, nbuckets):
                f.seek(bucket_offset + cur_bucket * 4)
                bucket_start_b = f.read(4)
                print('Start of Bucket', cur_bucket, int.from_bytes(bucket_start_b, sys.byteorder, signed=False))
                bucket_start = int.from_bytes(bucket_start_b, sys.byteorder, signed=False)
                bucket_start -= 1
                f.seek(bucket_offset + cur_bucket * 4)
                f.write(bucket_start.to_bytes(4, sys.byteorder))

            ### remove deletet entry from bucket ###
            # check hash
            sym_nr = dynsym_nr - symoffset
            f.seek(bucket_offset + nbuckets * 4 + sym_nr * 4)
            bucket_hash_b = f.read(4)
            bucket_hash = int.from_bytes(bucket_hash_b, sys.byteorder, signed=False)
            if((bucket_hash & ~0x1) != (func_hash & ~0x1)):
                print('Sth extremly terrible went wrong!!! OH NOOOOO!!!!')
                print('calculated hash:', hex(func_hash), 'read hash:', hex(bucket_hash))
                print('Sym_nr:', sym_nr, symtab_nr, symoffset)

            # copy all entrys afterwards up by one
            total_ent = total_ent_sym - symoffset
            for cur_hash_off in range(sym_nr, total_ent):
                f.seek(bucket_offset + nbuckets * 4 + (cur_hash_off + 1) * 4)
                cur_hash_b = f.read(4)
                f.seek(bucket_offset + nbuckets * 4 + cur_hash_off * 4)
                f.write(cur_hash_b)

            # remove double last value
            f.seek(bucket_offset + nbuckets * 4 + total_ent * 4)
            for count in range(0, 4):
                f.write(chr(0x0).encode('ascii'))

            # if last bit is set, set it at the value before
            if((bucket_hash & ~1) == 1 and sym_nr != 0):
                f.seek(bucket_offset + nbuckets * 4 + (sym_nr - 1) * 4)
                new_tail_b = f.read(4)
                new_tail = int.from_bytes(new_tail_b, sys.byteorder, signed=False)
                # set with 'or' if already set
                new_tail = new_tail ^ 0x00000001
                f.seek(bucket_offset + nbuckets * 4 + (sym_nr - 1) * 4)
                f.write(new_tail.to_bytes(4, sys.byteorder))


def process_file(filename, func_name):
    start_addr = 0
    size = 0

    print('\nProcessing file:', filename, ' Function to remove:', func_name)
    with open(filename, 'r+b') as f:
    # TODO check for object-type
        elffile = ELFFile(f)
        # check for supported architecture
        if(elffile.header['e_machine'] != 'EM_X86_64' and elffile.header['e_machine'] != 'EM_386'):
            error_message("Unsupported architecture: " + elffile.header['e_machine'])

        sect_no = -1
        for sect in elffile.iter_sections():
            sect_no += 1
            if not isinstance(sect, SymbolTableSection):
                continue
            print('Searching in section:', sect.name)

            #### Search for function in Symbol Table ####
            entry_cnt = 0
            found = 0
            for symbol in sect.iter_symbols():
                if symbol.name == func_name:
                    start_addr = symbol.entry['st_value']
                    size = symbol.entry['st_size']
                    found = 1
                    break
                entry_cnt += 1

            # Symbol not found -> search next section
            if found == 0:
                print('    No symbol \'', func_name, '\' found!')
                continue

            # Symbol not a function -> end program
            if symbol['st_info']['type'] != 'STT_FUNC':
                mes = "Found Symbol is not of type Function, but of type " + symbol['st_info']['type'] + "!"
                error_message(mes)

            print('    Function found: ', symbol.name, ' at', symbol.entry['st_value'], ' with size', symbol.entry['st_size'])

            #### Overwrite Symbol Table entry ####
            # if function was found
            max_entrys = (sect.header['sh_size'] // sect.header['sh_entsize'])

            # TODO call only for dynsym and if '.gnu.hash' section exists and symbol was found
            if(sect.name == '.dynsym'):
                edit_gnu_hashtable(func_name, elffile, f, entry_cnt, max_entrys)

            if entry_cnt != max_entrys:
                print('    Deleting Table Entry')

                # TODO deletion of table entry breaks the library
                # push up all entrys
                for cur_entry in range(entry_cnt + 1, max_entrys):
                    f.seek(sect.header['sh_offset'] + (cur_entry * sect.header['sh_entsize']))
                    read_bytes = f.read(sect.header['sh_entsize'])
                    f.seek(sect.header['sh_offset'] + ((cur_entry - 1) * sect.header['sh_entsize']))
                    f.write(read_bytes)

                # last entry -> set to 0x0
                f.seek(sect.header['sh_offset'] + ((max_entrys - 1) * sect.header['sh_entsize']))
                for count in range(0, sect.header['sh_entsize']):
                    f.write(chr(0x0).encode('ascii'))

                # set new table size in header
                head_entsize = elffile['e_shentsize']
                off_to_head = elffile['e_shoff'] + (head_entsize * sect_no)

                if(elffile.header['e_machine'] == 'EM_X86_64'):
                    # 64 Bit - seek to current section header + offset to size of section
                    f.seek(off_to_head + 32)
                    size_bytes = f.read(8)
                    value = int.from_bytes(size_bytes, sys.byteorder, signed=False)
                    value -= sect.header['sh_entsize']
                    if value < sect.header['sh_entsize']:
                        error_message('Size of section')
                    f.seek(off_to_head + 32)
                    f.write(value.to_bytes(8, sys.byteorder))
                elif(elffile.header['e_machine'] == 'EM_386'):
                    # TODO test 32 Bit
                    f.seek(off_to_head + 20)
                    size_bytes = f.read(4)
                    value = int.from_bytes(size_bytes, sys.byteorder, signed=False)
                    value -= sect.header['sh_entsize']
                    if value <= sect.header['sh_entsize']:
                        error_message('Size of section strange')
                    f.seek(off_to_head + 20)
                    f.write(value.to_bytes(4, sys.byteorder))
                else:
                    error_message('Unsupported architecture: ' + elffile.header['e_machine'] + '!')

#                #### Temporary: set entry to 0x0 and type to weak ####
#                # (temporary) set table entry to 0x0
#                f.seek(sect.header['sh_offset'] + ((entry_cnt) * sect.header['sh_entsize']))
#                for count in range(0, sect.header['sh_entsize']):
#                    f.write(chr(0x0).encode('ascii'))
#
#                # (temporary) set entry type to weak, only 64 Bit!
#                f.seek(sect.header['sh_offset'] + ((entry_cnt) * sect.header['sh_entsize']) + 4)
#                f.write(chr(0x20).encode('ascii'))

            else:
                print('    Function not found')

        #### Overwrite function with null bytes ####
        if start_addr != 0 and size != 0:
            print('Overwriting function with Null Bytes!')
            f = open(filename, "r+b")
            f.seek(start_addr)
            for count in range(0, size):
                f.write(chr(0x0).encode('ascii'))

        f.close()

if __name__ == '__main__':
    for function in sys.argv[2:]:
        process_file(sys.argv[1], function)
