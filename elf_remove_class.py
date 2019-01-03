#!/usr/bin/python3

import sys
import binascii
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.elf.sections import NullSection
from elftools.elf.sections import StringTableSection
from elftools.elf.sections import SymbolTableSection

class ELFRemove:

    '''
    Function:   __init__
    Parameter:  filename = path to elf library to be processed
            debug    = Boolean, if True, debug output is printed

    Description: Is automatically called on object creation.
             Opens the given library and searches for the requiered sections.
    '''
    def __init__(self, filename, debug = False):
        self._debug = debug
        self._f = open(filename, 'r+b')
        self._elffile = ELFFile(self._f)
        self._gnu_hash = None
        self.dynsym = None
        self.symtab = None
        self._gnu_version = None

        #### check for supported architecture ####
        if(self._elffile.header['e_machine'] != 'EM_X86_64' and self._elffile.header['e_machine'] != 'EM_386'):
            raise Exception('Wrong Architecture!')

        section_no = 0
        # search for needed sections and remember (Section-Object, Section Nr., Version Counter)
        for sect in self._elffile.iter_sections():
            if(sect.name == '.gnu.hash'):
                self._log('    Found \'GNU_HASH\' section!')
                self._gnu_hash = (sect, section_no, 0)
            if(sect.name == '.dynsym'):
                self._log('    Found \'DYNSYM\' section!')
                self.dynsym = (sect, section_no, 0)
            if(sect.name == '.symtab'):
                self._log('    Found \'SYMTAB\' section!')
                self.symtab = (sect, section_no, 0)
            if(sect.name == '.gnu.version'):
                self._log('    Found \'GNU_VERSION\' section!')
                self._gnu_version = (sect, section_no, 0)
            if(sect.name == '.rel.plt' or sect.name == '.rela.plt'):
                self._log('    Found \'RELA_PLT\' section!')
                self._rel_plt = (sect, section_no, 0)
            section_no += 1
        if(self.dynsym == None and self.symtab == None):
            raise Exception("No symbol table found!")

    def __del__(self):
        self._f.close()

    def _log(self, mes):
        if(self._debug):
            print('DEBUG: ' + mes)

    def _gnuhash(self, func_name):
        h = 5381
        for c in func_name:
            h = (h << 5) + h + ord(c)
            h = h & 0xFFFFFFFF
        return h

    '''
    Function:   change_section_size
    Parameter:  section = Tuple with section object and index (object, index)
                size    = size in Bytes

    Description: Decreases the size of the given section in its header by 'size' bytes
    '''
    def _change_section_size(self, section, size):
        head_entsize = self._elffile['e_shentsize']
        off_to_head = self._elffile['e_shoff'] + (head_entsize * section[1])
        if(self._elffile.header['e_machine'] == 'EM_X86_64'):
            # 64 Bit - seek to current section header + offset to size of section
            self._f.seek(off_to_head + 32)
            size_bytes = self._f.read(8)
            value = int.from_bytes(size_bytes, sys.byteorder, signed=False)
            value -= size
            if value < size:
                raise Exception('Size of section broken')
            self._f.seek(off_to_head + 32)
            self._f.write(value.to_bytes(8, sys.byteorder))
        elif(self._elffile.header['e_machine'] == 'EM_386'):
            # 32 Bit
            self._f.seek(off_to_head + 20)
            size_bytes = self._f.read(4)
            value = int.from_bytes(size_bytes, sys.byteorder, signed=False)
            value -= size
            if value <= size:
                raise Exception('Size of section broken')
            self._f.seek(off_to_head + 20)
            self._f.write(value.to_bytes(4, sys.byteorder))

    def _edit_rel_plt(self, sym_nr):
        if(self._rel_plt != None):
            ent_size = 0
            ent_cnt = 0
            total_entries = self._rel_plt[0].num_relocations()
            offset = self._rel_plt[0].header['sh_offset']
            to_remove = -1

            if(self._elffile.header['e_machine'] == 'EM_X86_64'):
                ent_size = 24 # Elf64_rela struct size, x64 always rela?
            else:
                ent_size = 8 # Elf32_rel struct size, x86 always rel

            for reloc in self._rel_plt[0].iter_relocations():
                #print("Reloc: (%s)" % 'RELA' if reloc.is_RELA() else 'REL')
                
                # case: delete entry
                if(reloc['r_info_sym'] == sym_nr):
                    #print("Reloc offset: " + str(reloc['r_offset']) + " type: " + str(reloc['r_info_type']) + " sym: " + str(reloc['r_info_sym']))
                    if(to_remove != -1):
                        raise Exception("double value in rel.plt")
                    to_remove = ent_cnt

                # case: entry_num > removed_entry -> count down sym_nr by 1
                elif(reloc['r_info_sym'] > sym_nr):
                    self._f.seek(offset + ent_cnt * ent_size)
                    cur_ent_b = self._f.read(ent_size)
                    if(ent_size == 8):
                        addr, info = struct.unpack('<Ii', cur_ent_b)
                        old_sym = info >> 8
                        old_sym -= 1
                        info = (old_sym << 8) + (info & 0xFF)
                        cur_ent_b = struct.pack('<Ii', addr, info)
                    else:
                        addr, info, addent = struct.unpack('<QqQ', cur_ent_b)
                        old_sym = info >> 32
                        old_sym -= 1
                        info = (old_sym << 32) + (info & 0xFFFFFFFF)
                        cur_ent_b = struct.pack('<QqQ', addr, info, addent)

                    self._f.seek(offset + ent_cnt * ent_size)
                    self._f.write(cur_ent_b)
                ent_cnt += 1
           
            if(to_remove != -1):
                for cur_ent in range(to_remove, total_entries):
                    self._f.seek(offset + (cur_ent + 1) * ent_size)
                    cur_ent_b = self._f.read(ent_size)
                    
                    addr, info = struct.unpack('<Ii', cur_ent_b)
                    old_sym = info >> 8
                    print("Read value: " + str(old_sym))
                    
                    self._f.seek(offset + cur_ent * ent_size)
                    self._f.write(cur_ent_b)
                #self._f.seek(offset + (ent_cnt + 1) * ent_size)
                #cur_ent_b = self._f.read(ent_size)
                #self._f.seek(offset + ent_cnt * ent_size)
                #self._f.write(cur_ent_b)

                # remove double last value
                self._f.seek(offset + (total_entries - 1) * ent_size)
                for count in range(0, ent_size):
                    self._f.write(chr(0x0).encode('ascii'))
                self._change_section_size(self._rel_plt, ent_size)


    '''
    Function:   _edit_gnu_versions
    Parameter:  dynsym_nr       = nr of the given symbol in the dynsym table
                total_sym_count = total entries of th dynsym section

    Description: removes the given offset from the 'gnu.version' section
    '''
    def _edit_gnu_versions(self, dynsym_nr, total_sym_cnt):
        # should be the same for 32-Bit
        if(self._gnu_version != None):
            ent_size = 2 # 2 Bytes for each entry (Elf32_half & Elf64_half)
            offset = self._gnu_version[0].header['sh_offset']

            # copy all following entries up by one
            for cur_ent in range(dynsym_nr, total_sym_cnt):
                self._f.seek(offset + (cur_ent + 1) * ent_size)
                cur_ent_b = self._f.read(ent_size)
                self._f.seek(offset + cur_ent * ent_size)
                self._f.write(cur_ent_b)

            # remove double last value
            self._f.seek(offset + (total_sym_cnt - 1) * ent_size)
            for count in range(0, ent_size):
                self._f.write(chr(0x0).encode('ascii'))

            # change section size in header
            self._change_section_size(self._gnu_version, ent_size)

    '''
    Function:   _edit_gnu_hashtable
    Parameter:  symbol_name   = name of the Symbol to be removed
                dynsym_nr     = nr of the given symbol in the dynsym table
                total_ent_sym = total entries of th dynsym section

    Description: removes the given Symbol from the 'gnu.hash' section
    '''
    def _edit_gnu_hashtable(self, symbol_name, dynsym_nr, total_ent_sym):
        if(self._gnu_hash != None):
            bloom_entry = 8
            if(self._elffile.header['e_machine'] == 'EM_386'):
                bloom_entry = 4

            self._f.seek(self._gnu_hash[0].header['sh_offset'])
            nbuckets_b = self._f.read(4)
            symoffset_b = self._f.read(4)
            bloomsize_b = self._f.read(4)
            #bloomshift_b = f.read(4)

            nbuckets = int.from_bytes(nbuckets_b, sys.byteorder, signed=False)
            symoffset = int.from_bytes(symoffset_b, sys.byteorder, signed=False)
            bloomsize = int.from_bytes(bloomsize_b, sys.byteorder, signed=False)
            #bloomshift = int.from_bytes(bloomshift_b, sys.byteorder, signed=False)

            #bloom_hex = self._f.read(bloomsize * 8)

            ### calculate hash and bucket ###
            func_hash = self._gnuhash(symbol_name)
            bucket_nr = func_hash % nbuckets
            self._log("\t" + symbol_name + ': adjust gnu_hash_section, hash = ' + hex(func_hash) + ' bucket = ' + str(bucket_nr))

            bucket_offset = self._gnu_hash[0].header['sh_offset'] + 4 * 4 + bloomsize * bloom_entry

            ### Set new Bucket start values ###
            for cur_bucket in range(bucket_nr, nbuckets - 1):
                self._f.seek(bucket_offset + (cur_bucket + 1) * 4)
                bucket_start_b = self._f.read(4)
                bucket_start = int.from_bytes(bucket_start_b, sys.byteorder, signed=False)
                # TODO: why is this possible (libcurl.so.4.5.0 - remove all)
                if(bucket_start == 0):
                    continue
                bucket_start -= 1
                self._f.seek(bucket_offset + (cur_bucket + 1) * 4)
                self._f.write(bucket_start.to_bytes(4, sys.byteorder))

            ### remove deletet entry from bucket ###
            # check hash
            sym_nr = dynsym_nr - symoffset
            if(sym_nr < 0):
                raise Exception('Function index out of bounds for gnu_hash_section! Index: ' + str(sym_nr))
            self._f.seek(bucket_offset + nbuckets * 4 + sym_nr * 4)
            bucket_hash_b = self._f.read(4)

            bucket_hash = int.from_bytes(bucket_hash_b, sys.byteorder, signed=False)

            # if this happens, sth on the library or hash function is broken!
            if((bucket_hash & ~0x1) != (func_hash & ~0x1)):
                raise Exception('calculated hash: ' + str(hex(func_hash)) + ' read hash: ' + str(hex(bucket_hash)))

            # copy all entrys afterwards up by one
            total_ent = total_ent_sym - symoffset
            for cur_hash_off in range(sym_nr, total_ent):
                self._f.seek(bucket_offset + nbuckets * 4 + (cur_hash_off + 1) * 4)
                cur_hash_b = self._f.read(4)
                self._f.seek(bucket_offset + nbuckets * 4 + cur_hash_off * 4)
                self._f.write(cur_hash_b)

            # remove double last value
            self._f.seek(bucket_offset + nbuckets * 4 + total_ent * 4)
            for count in range(0, 4):
                self._f.write(chr(0x0).encode('ascii'))

            # if last bit is set, set it at the value before
            if((bucket_hash & 0x1) == 1 and sym_nr != 0):
                self._f.seek(bucket_offset + nbuckets * 4 + (sym_nr - 1) * 4)
                new_tail_b = self._f.read(4)
                new_tail = int.from_bytes(new_tail_b, sys.byteorder, signed=False)
                # set with 'or' if already set
                new_tail = new_tail ^ 0x00000001
                self._f.seek(bucket_offset + nbuckets * 4 + (sym_nr - 1) * 4)
                self._f.write(new_tail.to_bytes(4, sys.byteorder))

            # change section size in header
            self._change_section_size(self._gnu_hash, 4)

    '''
    Function:   remove_from_section
    Parameter:  section     = section tuple (self.dynsym, self.symtab)
                collection  = list of symbol tuples from 'collect_symbols'
                overwrite   = Boolean, True for overwriting text segment wit Null Bytes
    Returns:    nr of symbols removed

    Description: removes the symbols from the given section
    '''
    def remove_from_section(self, section, collection, overwrite=True):
        if(section == None):
            raise Exception('Section not available!')

        # sort list by offset in symbol table
        # otherwise the index would be wrong after one Element was removed
        sorted_list = sorted(collection, reverse=True, key=lambda x: x[1])

        removed = 0
        max_entrys = (section[0].header['sh_size'] // section[0].header['sh_entsize'])

        self._log('In \'' + section[0].name + '\' section:')
        for symbol_t in sorted_list:
            # check if section was changed between the collection and removal of Symbols
            if(symbol_t[4] != section[2]):
                raise Exception('symbol_collection was generated for older revision of ' + section[0].name)
            #### Overwrite Symbol Table entry ####
            # edit gnu_hash table, gnu_versions and relocation table but only for dynsym section
            if(section[0].name == '.dynsym'):
                self._edit_gnu_hashtable(symbol_t[0], symbol_t[1], max_entrys)
                self._edit_gnu_versions(symbol_t[1], max_entrys)
                self._edit_rel_plt(symbol_t[1])

            self._log('\t' + symbol_t[0] + ': deleting table entry')

            # push up all entrys
            for cur_entry in range(symbol_t[1] + 1, max_entrys):
                self._f.seek(section[0].header['sh_offset'] + (cur_entry * section[0].header['sh_entsize']))
                read_bytes = self._f.read(section[0].header['sh_entsize'])
                self._f.seek(section[0].header['sh_offset'] + ((cur_entry - 1) * section[0].header['sh_entsize']))
                self._f.write(read_bytes)

            # last entry -> set to 0x0
            self._f.seek(section[0].header['sh_offset'] + ((max_entrys - 1) * section[0].header['sh_entsize']))
            for count in range(0, section[0].header['sh_entsize']):
                self._f.write(chr(0x0).encode('ascii'))

            #### Overwrite function with null bytes ####
            if(overwrite):
                if symbol_t[2] != 0 and symbol_t[3] != 0:
                    self._log('\t' + symbol_t[0] + ': overwriting text segment with null bytes')
                    self._f.seek(symbol_t[2])
                    for count in range(0, symbol_t[3]):
                        self._f.write(chr(0x0).encode('ascii'))
                        #pass
            removed += 1;
            max_entrys -= 1

        self._change_section_size(section, removed * section[0].header['sh_entsize'])
        section = (section[0], section[1], section[2] + 1)
        return removed

    '''
    Function:   collect_symbols_by_name
    Parameter:  section     = symbol table to search in (self.symtab, self.dynsym)
                symbol_list = list of symbol names to be collected
                complement  = Boolean, True: all symbols except given list are collected
    Returns:    collection of matching Symbols in given symboltable
                NOTE: collection contains indices of Symbols -> all collections are invalidated
                      after symboltable changes.

    Description: removes the symbols from the given section
    '''
    def collect_symbols_by_name(self, section, symbol_list, complement=False):
        self._log('Searching in section: ' + section[0].name)

        #### Search for function in Symbol Table ####
        entry_cnt = -1
        found_symbols = []

        for symbol in section[0].iter_symbols():
            entry_cnt += 1
            if(complement):
                if symbol.name not in symbol_list:
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
            else:
                if symbol.name in symbol_list:
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
        return found_symbols

    def collect_symbols_by_address(self, section, address_list, complement=False):
        self._log('Searching in section: ' + section[0].name)

        #### Search for function in Symbol Table ####
        entry_cnt = -1
        found_symbols = []

        for symbol in section[0].iter_symbols():
            entry_cnt += 1
            if(complement):
                if symbol.entry['st_value'] not in address_list:
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
            else:
                if symbol.entry['st_value'] in address_list:
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
        return found_symbols

    def print_collection_info(self, collection, full=True):
        if(full):
            print('Symbols in collection: ' + str(len(collection)))
            print('Name\t\t| Offset | Start Addr   | Size  | Revision')
            print('-----------------------------------------------------------')
            for sym in collection:
                print(sym[0] + '\t\t| ' + str(sym[1]) + '\t | ' + str(sym[2]) + '\t| ' + str(hex(sym[3])) + '\t| ' + str(sym[4]))
        else:
            for sym in collection:
                print(sym[0] + " ", end="", flush=True)
            print("")

    def get_collection_names(self, collection):
        symbols = []
        for sym in collection:
            symbols.append(sym[0])
        return symbols
