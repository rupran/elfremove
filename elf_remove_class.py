#!/usr/bin/python3

import sys
import binascii
import struct
import collections

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, NoteSection, StringTableSection, SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.enums import ENUM_D_TAG_COMMON
from elftools.elf.hash import HashSection


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
        self._f = open(filename, 'r+b', buffering=0)
        self._elffile = ELFFile(self._f)
        self._byteorder = 'little' if self._elffile.little_endian else 'big'
        self._gnu_hash = None
        self.dynsym = None
        self.symtab = None
        self._gnu_version = None
        self._rel_plt = None
        self._rel_dyn = None
        self._elf_hash = None
        self._dynamic = None
        self._blacklist = ["_init", "_fini"]
        self._reloc_list = None

        #### check for supported architecture ####
        if(self._elffile.header['e_machine'] != 'EM_X86_64' and self._elffile.header['e_machine'] != 'EM_386'):
            raise Exception('Wrong Architecture!')

        section_no = 0
        # search for supported sections and remember (Section-Object, Section Nr., Version Counter)
        for sect in self._elffile.iter_sections():
            if(sect.name == '.gnu.hash'):
                self._log('    Found \'GNU_HASH\' section!')
                self._gnu_hash = (sect, section_no, 0)
            if(sect.name == '.hash'):
                self._log('    Found \'HASH\' section!')
                self._elf_hash = (sect, section_no, 0)
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
            if(sect.name == '.rel.dyn' or sect.name == '.rela.dyn'):
                self._log('    Found \'RELA_DYN\' section!')
                self._rel_dyn = (sect, section_no, 0)
            if(sect.name == '.dynamic'):
                self._log('    Found \'DYNAMIC\' section!')
                self._dynamic = (sect, section_no, 0)
            section_no += 1

        # fallback if section headers have been stripped from the binary
        if(self.dynsym == None and self.symtab == None):
            self._log("No section headers found in ELF, fallback to dynamic segment!")
            for seg in self._elffile.iter_segments():
                if(isinstance(seg, DynamicSegment)):

                    # try to build symtab section from dynamic segment information
                    size = seg.num_symbols() * seg.elfstructs.Elf_Sym.sizeof()
                    _, offset = seg.get_table_offset('DT_SYMTAB')
                    self.dynsym = (self._build_symtab_section('.dynsym', offset, size, seg.elfstructs.Elf_Sym.sizeof(), seg._get_stringtable()), -1, 0)
                    self._log('    Found \'DYNSYM\' section!')

                    # search for all supported sections and build section object with needed entries
                    rel_plt_off = rel_plt_size = rel_dyn_off = rel_dyn_size = 0
                    for tag in seg.iter_tags():
                        if(tag['d_tag'] == "DT_GNU_HASH"):
                            self._log('    Found \'GNU_HASH\' section!')
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._gnu_hash = ((self._build_section('.gnu.hash', offset, -1, 0, 0)), -1, 0)
                        if(tag['d_tag'] == "DT_HASH"):
                            self._log('    Found \'HASH\' section!')
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._elf_hash = ((self._build_section('.hash', offset, -1, 0, 0)), -1, 0)
                        if(tag['d_tag'] == "DT_VERSYM"):
                            self._log('    Found \'GNU_VERSION\' section!')
                            size = seg.num_symbols() * 2
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._gnu_version = (self._build_section('.gnu.version', offset, size, 2, 0), -1, 0)

                        if(tag['d_tag'] == "DT_JMPREL"):
                            _, rel_plt_off = seg.get_table_offset(tag['d_tag'])
                        if(tag['d_tag'] == "DT_PLTRELSZ"):
                            rel_plt_size = tag['d_val']

                        if(tag['d_tag'] == "DT_RELA" or tag['d_tag'] == "DT_REL"):
                            _, rel_dyn_off = seg.get_table_offset(tag['d_tag'])
                        if(tag['d_tag'] == "DT_RELASZ" or tag['d_tag'] == "DT_RELSZ"):
                            rel_dyn_size = tag['d_val']

                    ent_size = seg.elfstructs.Elf_Rela.sizeof() if (self._elffile.header['e_machine'] == 'EM_X86_64') else seg.elfstructs.Elf_Rel.sizeof()
                    sec_name = '.rela.' if (self._elffile.header['e_machine'] == 'EM_X86_64') else '.rel.'
                    sec_out_name = 'RELA_' if (self._elffile.header['e_machine'] == 'EM_X86_64') else 'REL_'
                    sec_type = 'SHT_RELA' if (self._elffile.header['e_machine'] == 'EM_X86_64') else 'SHT_REL'

                    if(rel_plt_off != 0 and rel_plt_size != 0):
                        self._log('    Found \'' + sec_out_name + 'PLT\' section!')
                        self._rel_plt = (self._build_relocation_section(sec_name + 'plt', rel_plt_off, rel_plt_size, ent_size, sec_type), -1, 0)
                    if(rel_dyn_off != 0 and rel_dyn_size != 0):
                        self._log('    Found \'' + sec_out_name + 'DYN\' section!')
                        self._rel_dyn = (self._build_relocation_section(sec_name + 'dyn', rel_dyn_off, rel_dyn_size, ent_size, sec_type), -1, 0)


    def __del__(self):
        self._f.close()

    def _log(self, mes):
        if(self._debug):
            print('DEBUG: ' + mes)

    '''
    Hash-Functions for GNU and standard hash
    '''
    def _elfhash(self, func_name):
        h = 0
        g = 0
        for c in func_name:
            h = (h << 4) + ord(c)
            h = h & 0xFFFFFFFF
            g = h & 0xF0000000
            if(g != 0):
                h = h ^ (g >> 24)
            h = h & ~g
        return h

    def _gnuhash(self, func_name):
        h = 5381
        for c in func_name:
            h = (h << 5) + h + ord(c)
            h = h & 0xFFFFFFFF
        return h

    '''
    Helper functions for section-object creation
    '''
    def _build_relocation_section(self, name, off, size, entsize, sec_type):
        return RelocationSection(self._build_header(off, size, entsize, name, sec_type), name, self._elffile)

    def _build_symtab_section(self, name, off, size, entsize, stringtable):
        return SymbolTableSection(self._build_header(off, size, entsize, name, 0), name, self._elffile, stringtable)

    def _build_section(self, name, off, size, entsize, shtype):
        return Section(self._build_header(off, size, entsize, name, shtype), name, self._elffile)

    def _build_header(self, off, size, entsize, name, shtype):
        # build own header
        header = {'sh_name': name, 'sh_type': shtype, 'sh_flags': 0, 'sh_addr': 0, 'sh_offset': off
            , 'sh_size': size, 'sh_link': 0, 'sh_info': 0, 'sh_addralign': 0, 'sh_entsize': entsize}

        return header

    def _dyn_get_section_info(self, dyn_seg, sec_name):
        ptr, offset = dyn_seg.get_table_offset(sec_name)
        if ptr is None or offset is None:
            raise Exception('Dynamic segment does not contain \'' + sec_name + '\'')

        nearest_ptr = None
        # entries with value interpreted as pointer (https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html)
        dptr_entries = [3, 4, 5, 6, 7, 12, 13, 17, 21, 23, 25, 26, 32
            ,0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x6ffffefd, 0x6ffffefe, 0x6ffffeff
            ,0x6ffffffe, 0x6ffffffc]
        for tag in dyn_seg.iter_tags():
            tag_ptr = tag['d_ptr']

            # fix for symtab
            if (ENUM_D_TAG_COMMON[tag['d_tag']] not in dptr_entries):
                continue

            if (tag_ptr > ptr and (nearest_ptr is None or nearest_ptr > tag_ptr)):
                nearest_ptr = tag_ptr

        if nearest_ptr is None:
            # Use the end of segment that contains DT_SYMTAB.
            for segment in dyn_seg.elffile.iter_segments():
                if (segment['p_vaddr'] <= tab_ptr and
                        tab_ptr <= (segment['p_vaddr'] + segment['p_filesz'])):
                    nearest_ptr = segment['p_vaddr'] + segment['p_filesz']

        if nearest_ptr is None:
            raise Exception('Could not determine the size of \'' + name + '\' section.')
        return (nearest_ptr - ptr, offset)


    '''
    Function:   _change_section_size
    Parameter:  section = Tuple with section object and index (object, index)
                size    = size in Bytes

    Description: Decreases the size of the given section in its header by 'size' bytes
    '''
    def _change_section_size(self, section, size):
        # can't change section header f no header in elffile
        if(section[1] == -1):
            return
        head_entsize = self._elffile['e_shentsize']
        off_to_head = self._elffile['e_shoff'] + (head_entsize * section[1])
        if(self._elffile.header['e_machine'] == 'EM_X86_64'):
            # 64 Bit - seek to current section header + offset to size of section
            self._f.seek(off_to_head + 32)
            size_bytes = self._f.read(8)
            value = int.from_bytes(size_bytes, self._byteorder, signed=False)
            if value < size:
                raise Exception('Size of section broken! Section: ' + section[0].name + ' Size: ' + value)
            value -= size
            self._f.seek(off_to_head + 32)
            self._f.write(value.to_bytes(8, self._byteorder))
        elif(self._elffile.header['e_machine'] == 'EM_386'):
            # 32 Bit
            self._f.seek(off_to_head + 20)
            size_bytes = self._f.read(4)
            value = int.from_bytes(size_bytes, self._byteorder, signed=False)
            if value <= size:
                raise Exception('Size of section broken')
            value -= size
            self._f.seek(off_to_head + 20)
            self._f.write(value.to_bytes(4, self._byteorder))


    def _shrink_dynamic_tag(self, target_tag, amount):
        dynamic_section = self._dynamic[0]
        relasz = [idx for idx, tag in enumerate(dynamic_section.iter_tags()) if tag['d_tag'] == target_tag]
        if not relasz:
            return
        f_off = dynamic_section._offset + relasz[0] * dynamic_section._tagsize
        self._f.seek(f_off)
        val = self._f.read(dynamic_section._tagsize)
        struct_string = '<' if self._byteorder == 'little' else '>'
        if dynamic_section._tagsize == 8:
            struct_string += 'iI'
        else:
            struct_string += 'qQ'
        tagno, sz = struct.unpack(struct_string, val)
        new_val = struct.pack(struct_string, tagno, sz - amount)
        self._f.seek(f_off)
        self._f.write(new_val)

    '''
    Function:   _edit_rel_sect
    Parameter:  section = Tuple with section object and index (object, index)
                sym_nr  = index of removed entry in dynsym

    Description: adapts the entries of the given relocation section to the changed dynsym
    '''
    def _edit_rel_sect(self, section, sym_nr, sym_addr, push=False):
        if(section != None):
            ent_size = 0
            ent_cnt = 0

            offset = section[0].header['sh_offset']

            if(self._elffile.header['e_machine'] == 'EM_X86_64'):
                ent_size = 24 # Elf64_rela struct size, x64 always rela?
            else:
                ent_size = 8 # Elf32_rel struct size, x86 always rel

            if self._reloc_list is None:
                self._reloc_list = list(section[0].iter_relocations())
            reloc_list = self._reloc_list
            cur_idx = 0
            removed = 0
            #print('list based removal for {}'.format(hex(sym_addr)))
            while cur_idx < len(reloc_list):
                reloc = reloc_list[cur_idx]
                if reloc.entry['r_info_sym'] == sym_nr or reloc.entry['r_addend'] == sym_addr:
                    if push:
                        reloc_list.pop(cur_idx)
                        removed += 1
                        continue
                    else:
                        reloc.entry['r_info_sym'] = 0
                        if ent_size == 24:
                            reloc.entry['r_addend'] = 0
                elif reloc.entry['r_info_sym'] > sym_nr:
                    new_sym = reloc.entry['r_info_sym'] - 1
                    old_type = reloc.entry['r_info_type']
                    if ent_size == 8:
                        reloc.entry['r_info'] = new_sym << 8 | (old_type & 0xFF)
                    else:
                        reloc.entry['r_info'] = new_sym << 32 | (old_type & 0xFFFFFFFF)
                    reloc.entry['r_info_sym'] = new_sym

                cur_idx += 1

            # Write whole section out at once
            self._f.seek(offset)
            endianness = '<' if self._byteorder == 'little' else '>'
            for reloc in reloc_list:
                if ent_size == 24:
                    cur_val = struct.pack(endianness + 'QqQ', reloc.entry['r_offset'],
                                          reloc.entry['r_info'], reloc.entry['r_addend'])
                else:
                    cur_val = struct.pack(endianness + 'Ii', reloc.entry['r_offset'],
                                          reloc.entry['r_info'])
                self._f.write(cur_val)

            # Change the size in the section header
            self._change_section_size(section, ent_size * removed)
            # the following is needed in order to lower the number of relocations
            # returned via iter_relocations() -> uses num_relocations() -> uses
            # _size to calculate the number
            section[0]._size -= (ent_size * removed)

            # Shrink the number of relocation entries in the DYNAMIC segment
            self._shrink_dynamic_tag('DT_RELASZ', ent_size * removed)


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
    Helper function to test the consitency of the standard hash section
    '''
    # temporary test function
    def test_hash_section(self):
        if(self._elf_hash != None):
            sect = HashSection(self._elffile.stream, self._elf_hash[0].header['sh_offset'], self._elffile)
            # print hash section
            for i in range (0, sect.params['nchains']):
                print(self.dynsym[0].get_symbol(i).name)

            # find every symbol in hash table
            for i in range(1, self.dynsym[0].num_symbols()):
                name = self.dynsym[0].get_symbol(i).name
                print("Check hash of symbol: " + name)
                sym_hash = self._elfhash(name)
                bucket = sym_hash % sect.params['nbuckets']
                cur_ptr = sect.params['buckets'][bucket]
                found = 0
                while(cur_ptr != 0):
                    if(self.dynsym[0].get_symbol(cur_ptr).name == name):
                        print("     Found!")
                        found = 1
                        break
                    cur_ptr = sect.params['chains'][cur_ptr]
                if(found == 0):
                    raise Exception("Symbol not found in bucket!!! Hash Section broken!")


    '''
    Function:   _edit_elf_hashtable
    Parameter:  symbol_name   = name of the Symbol to be removed
                dynsym_nr     = nr of the given symbol in the dynsym table
                total_ent_sym = total entries of th dynsym section

    Description: removes the given Symbol from the '.hash' section
    '''
    def _edit_elf_hashtable(self, symbol_name, dynsym_nr, total_ent_sym):
        if(self._elf_hash != None):
            sect = HashSection(self._elffile.stream, self._elf_hash[0].header['sh_offset'], self._elffile)
            func_hash = self._elfhash(symbol_name)
            bucket_nr = func_hash % sect.params['nbuckets']
            self._log("\t" + symbol_name + ': adjust hash_section, hash = ' + hex(func_hash) + ' bucket = ' + str(bucket_nr))

            # find symbol and remove entry from chain
            cur_ptr = sect.params['buckets'][bucket_nr]

            # case: first elem -> change start value of Bucket
            if(cur_ptr == dynsym_nr):
                sect.params['buckets'][bucket_nr] = sect.params['chains'][cur_ptr]
            else:
                while(cur_ptr != 0):
                    prev_ptr = cur_ptr
                    cur_ptr = sect.params['chains'][cur_ptr]
                    # case: middle and last element -> set pointer to next element in previous element
                    if(cur_ptr == dynsym_nr):
                        sect.params['chains'][prev_ptr] = sect.params['chains'][cur_ptr]
                        break
                    if(cur_ptr == 0):
                        raise Exception("Entry \'" + symbol_name + "\' not found in Hash Table! Hash Table is broken!")

            # delete entry and change pointer in list
            for i in range(dynsym_nr, (sect.params['nchains'] - 1)):
                sect.params['chains'][i] = sect.params['chains'][i + 1]
            sect.params['chains'][sect.params['nchains'] - 1] = 0
            sect.params['nchains'] -= 1

            for i in range(0, sect.params['nchains']):
                if(sect.params['chains'][i] >= dynsym_nr):
                    sect.params['chains'][i] -= 1

            for i in range(0, sect.params['nbuckets']):
                if(sect.params['buckets'][i] >= dynsym_nr):
                    sect.params['buckets'][i] -= 1

            # TODO -> do this just once when all changes have been made
            # write to file
            #  - nchain
            self._f.seek(self._elf_hash[0].header['sh_offset'] +  4)
            self._f.write(sect.params['nchains'].to_bytes(4, self._byteorder))

            # - buckets
            buckets_start = self._elf_hash[0].header['sh_offset'] + 8
            for i in range(0, sect.params['nbuckets']):
                self._f.seek(buckets_start + i * 4)
                self._f.write(sect.params['buckets'][i].to_bytes(4, self._byteorder))

            # - chains
            chains_start = self._elf_hash[0].header['sh_offset'] + 8 + sect.params['nbuckets'] * 4
            for i in range(0, sect.params['nchains']):
                self._f.seek(chains_start + i * 4)
                self._f.write(sect.params['chains'][i].to_bytes(4, self._byteorder))



    '''
    Function:   _edit_gnu_hashtable
    Parameter:  symbol_name   = name of the Symbol to be removed
                dynsym_nr     = nr of the given symbol in the dynsym table
                total_ent_sym = total entries of th dynsym section

    Description: removes the given Symbol from the '.gnu.hash' section
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

            nbuckets = int.from_bytes(nbuckets_b, self._byteorder, signed=False)
            symoffset = int.from_bytes(symoffset_b, self._byteorder, signed=False)
            bloomsize = int.from_bytes(bloomsize_b, self._byteorder, signed=False)
            #bloomshift = int.from_bytes(bloomshift_b, self._byteorder, signed=False)

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
                bucket_start = int.from_bytes(bucket_start_b, self._byteorder, signed=False)
                # TODO: why is this possible (libcurl.so.4.5.0 - remove all)
                if(bucket_start == 0):
                    continue
                bucket_start -= 1
                self._f.seek(bucket_offset + (cur_bucket + 1) * 4)
                self._f.write(bucket_start.to_bytes(4, self._byteorder))

            ### remove deletet entry from bucket ###
            # check hash
            sym_nr = dynsym_nr - symoffset
            if(sym_nr < 0):
                raise Exception('Function index out of bounds for gnu_hash_section! Index: ' + str(sym_nr))
            self._f.seek(bucket_offset + nbuckets * 4 + sym_nr * 4)
            bucket_hash_b = self._f.read(4)

            bucket_hash = int.from_bytes(bucket_hash_b, self._byteorder, signed=False)

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
                new_tail = int.from_bytes(new_tail_b, self._byteorder, signed=False)
                # set with 'or' if already set
                new_tail = new_tail ^ 0x00000001
                self._f.seek(bucket_offset + nbuckets * 4 + (sym_nr - 1) * 4)
                self._f.write(new_tail.to_bytes(4, self._byteorder))

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
    # TODO change -> no section should be needed!
    def remove_from_section(self, section, collection, overwrite=True):
        if(section == None):
            raise Exception('Section not available!')

        if(len(collection) == 0):
            return

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
                self._edit_elf_hashtable(symbol_t[0], symbol_t[1], max_entrys)
                self._edit_gnu_versions(symbol_t[1], max_entrys)
                self._edit_rel_sect(self._rel_plt, symbol_t[1], symbol_t[2])
                self._reloc_list = None
                self._edit_rel_sect(self._rel_dyn, symbol_t[1], symbol_t[2], push=True)

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

            #### Overwrite function with zeros ####
            if(overwrite):
                if symbol_t[2] != 0 and symbol_t[3] != 0:
                    self._log('\t' + symbol_t[0] + ': overwriting text segment with zeros')
                    self._f.seek(symbol_t[2])
                    for count in range(0, symbol_t[3]):
                        #self._f.write(chr(0x0).encode('ascii'))
                        self._f.write(b'\xcc')
            removed += 1;
            max_entrys -= 1


        self._change_section_size(section, removed * section[0].header['sh_entsize'])
        section = (section[0], section[1], section[2] + 1)
        return removed

    '''
    Function:   collect_symbols_by_name (and -_by_address)
    Parameter:  section     = symbol table to search in (self.symtab, self.dynsym)
                symbol_list = list of symbol names to be collected
                complement  = Boolean, True: all symbols except given list are collected
    Returns:    collection of matching Symbols in given symboltable
                NOTE: collection contains indices of Symbols -> all collections are invalidated
                      after symboltable changes.

    Description: removes the symbols from the given symboltable
    '''
    def collect_symbols_by_name(self, section, symbol_list, complement=False):
        self._log('Searching in section: ' + section[0].name)

        #### Search for function in Symbol Table ####
        entry_cnt = -1
        found_symbols = []

        for symbol in section[0].iter_symbols():
            entry_cnt += 1
            if(symbol.name in self._blacklist):
                continue
            if(complement):
                if(symbol.name not in symbol_list):
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_info']['bind'] == 'STB_WEAK' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
            else:
                if(symbol.name in symbol_list):
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_info']['bind'] == 'STB_WEAK' or size == 0):
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
            if(symbol.name in self._blacklist):
                continue
            # fix for section from dynamic segment
            if(complement):
                if(symbol.entry['st_value'] not in address_list):
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_info']['bind'] == 'STB_WEAK' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
            else:
                if(symbol.entry['st_value'] in address_list):
                    size = symbol.entry['st_size']
                    # Symbol not a function -> next
                    if(symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_info']['bind'] == 'STB_WEAK' or size == 0):
                        continue
                    # add all symbols to remove to the return list
                    # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                    found_symbols.append((symbol.name, entry_cnt, symbol.entry['st_value'], symbol.entry['st_size'], section[2]))
        return found_symbols

    '''
    Function:   overwrite local functions
    Parameter:  func_tuple_list = list of tupels with address and size information for to be removed local functions

    Description: overwrites the given functions in the text segment and removes the entries from symtab if present
    '''
    def overwrite_local_functions(self, func_tuple_list):
        for func in func_tuple_list:
            #### Overwrite function with null bytes ####
            self._log('\t' + str(func[0]) + ': overwriting text segment of local function')
            self._f.seek(func[0])

            for count in range(0, func[1]):
                self._f.write(b'\xCC')

        if(self.symtab != None):
            addr = [x[0] for x in func_tuple_list]
            collection = self.collect_symbols_by_address(self.symtab, addr)
            self.remove_from_section(self.symtab, collection, overwrite=False)

    '''
    Function:   print_collection_info
    Parameter:  collection = a collection of symbols returned from a collect_* function
                full       = true - print all debug information, false - only a file statistic
                local      = tuple list of local function which gets included in the statistics

    Description: prints informations for the given collection of symbols
    '''
    def print_collection_info(self, collection, full=True, local=None):
        if(full):
            if(local != None):
                print('Local Functions: ' + str(len(local)))
                line = "{0:<10} | {1:<6}"
                print(line.format("Address", "Size"))
                print(16 * '-')
                for func in local:
                    print(line.format(func[0], func[1]))

            maxlen = 0
            for x in collection:
                if(len(x[0]) > maxlen):
                    maxlen = len(x[0])
            print('Symbols in collection: ' + str(len(collection)))
            line = "{0:<" + str(maxlen) + "} | {1:<8} | {2:<10} | {3:<6} | {4:<6}"
            print(line.format("Name", "Offset", "StartAddr", "Size", "Rev."))
            print((maxlen + 40) * '-')
            for sym in collection:
                print(line.format(sym[0], sym[1], sym[2], hex(sym[3]), sym[4]))
        else:
            size_of_text = 0
            for section in self._elffile.iter_sections():
                if(section.name == '.text'):
                    size_of_text = section["sh_size"]

            # create dict for unique address values
            addr_dict = {}
            for ent in collection:
                addr_dict[ent[2]] = ent[3]

            if(local != None and len(local) > 0):
                for func in local:
                    addr_dict[func[0]] = func[1]

            total_b_rem = 0
            for k, v in addr_dict.items():
                #print(sym[0] + " ", end="", flush=True)
                total_b_rem += v

            dynsym_entrys = (self.dynsym[0].header['sh_size'] // self.dynsym[0].header['sh_entsize'])

            print("Total number of symbols in dynsym: " + str(dynsym_entrys))
            print("    Nr of symbols to remove: " + str(len(collection)))
            if(local != None and len(local) > 0):
                print("    Nr of local functions to remove: " + str(len(local)))
            if(size_of_text != 0):
                print("Total size of text Segment: " + str(size_of_text))
                print("    Nr of bytes overwritten: " + str(total_b_rem))
                print("    Percentage of code overwritte: " + str((total_b_rem / size_of_text) * 100))
            else:
                print("Size of text Segment not given in section header")

            #print(" & " + str(dynsym_entrys) + " & " + str(len(collection)) + " & " + str(len(local)) + " & " + str(size_of_text) + " & " + str(total_b_rem) + " & " + str((total_b_rem / size_of_text) * 100) + "\\% \\\\")

    '''
    helper functions
    '''
    def print_collection_addr(self, collection, local=None):
        # create dictionary to ensure no double values
        addr_dict = {}
        for ent in collection:
            addr_dict[ent[2]] = ent[3]
        if(local != None and len(local) > 0):
            for func in local:
                addr_dict[func[0]] = func[1]

        # sort by address
        ordered = collections.OrderedDict(sorted(addr_dict.items()))
        for k, v in ordered.items():
            print(str(k) + " " + str(v))

    def get_collection_names(self, collection):
        symbols = []
        for sym in collection:
            symbols.append(sym[0])
        return symbols
