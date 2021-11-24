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

import struct
import collections
import bisect
import logging
import os

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.hash import ELFHashTable, GNUHashTable
from elftools.elf.enums import ENUM_RELOC_TYPE_x64, ENUM_RELOC_TYPE_i386, \
    ENUM_DT_FLAGS, ENUM_DT_FLAGS_1
from libdebuginfod import DebugInfoD

class SectionWrapper:

    def __init__(self, section, index, version):
        self.section = section
        self.index = index
        self.version = version

class SymbolWrapper:

    def __init__(self, name, index, value, size, sec_version):
        self.name = name
        self.index = index
        self.value = value
        self.size = size
        self.sec_version = sec_version

class ELFRemove:

    '''
    Function:   __init__
    Parameter:  filename = path to elf library to be processed
            debug    = Boolean, if True, debug output is printed

    Description: Is automatically called on object creation.
             Opens the given library and searches for the requiered sections.
    '''
    def __init__(self, filename, open_mode='r+b'):
        self._f = open(filename, open_mode, buffering=0)
        self._elffile = ELFFile(self._f)
        self._byteorder = 'little' if self._elffile.little_endian else 'big'
        self._endianness = '<' if self._elffile.little_endian else '>'
        self._gnu_hash = None
        self.dynsym = None
        self.symtab = None
        self._gnu_version = None
        self._rel_plt = None
        self._rel_dyn = None
        self._elf_hash = None
        self._dynamic = None
        self._blacklist = ["_init", "_fini"]
        self._external_elf_fd = None

        #### check for supported architecture ####
        if self._elffile.header['e_machine'] != 'EM_X86_64' and self._elffile.header['e_machine'] != 'EM_386':
            raise Exception('Wrong Architecture!')

        logging.info('* creating removal class for file \'%s\'', filename)
        section_no = 0
        # search for supported sections and remember (Section-Object, Section Nr., Version Counter)
        for sect in self._elffile.iter_sections():
            if sect.name == '.gnu.hash':
                logging.debug('* Found \'GNU_HASH\' section!')
                self._gnu_hash = SectionWrapper(sect, section_no, 0)
            if sect.name == '.hash':
                logging.debug('* Found \'HASH\' section!')
                self._elf_hash = SectionWrapper(sect, section_no, 0)
            if sect.name == '.dynsym':
                logging.debug('* Found \'DYNSYM\' section!')
                self.dynsym = SectionWrapper(sect, section_no, 0)
            if sect.name == '.symtab':
                logging.debug('* Found \'SYMTAB\' section!')
                self.symtab = SectionWrapper(sect, section_no, 0)
            if sect.name == '.gnu.version':
                logging.debug('* Found \'GNU_VERSION\' section!')
                self._gnu_version = SectionWrapper(sect, section_no, 0)
            if sect.name == '.rel.plt' or sect.name == '.rela.plt':
                logging.debug('* Found \'RELA_PLT\' section!')
                self._rel_plt = SectionWrapper(sect, section_no, 0)
            if sect.name == '.rel.dyn' or sect.name == '.rela.dyn':
                logging.debug('* Found \'RELA_DYN\' section!')
                self._rel_dyn = SectionWrapper(sect, section_no, 0)
            if sect.name == '.dynamic':
                logging.debug('* Found \'DYNAMIC\' section!')
                self._dynamic = SectionWrapper(sect, section_no, 0)
            section_no += 1

        # Special case for wrong loader behaviour before glibc 2.23. Due to a
        # bug, the .rela.dyn and .rela.plt sections have to be continuous when
        # BIND_NOW is set or PLT relocations might remain unprocessed.
        self._need_continuous_relocations = False
        if self._dynamic:
            flags = list(self._dynamic.section.iter_tags('DT_FLAGS'))
            flags_1 = list(self._dynamic.section.iter_tags('DT_FLAGS_1'))
            bind_now = list(self._dynamic.section.iter_tags('DT_BIND_NOW'))
            if flags and flags[0].entry.d_val & ENUM_DT_FLAGS['DF_BIND_NOW'] or \
                    flags_1 and flags_1[0].entry.d_val & ENUM_DT_FLAGS_1['DF_1_NOW'] or \
                    bind_now:
                # BIND_NOW, check environment variable or .note.ABI-tag
                if os.environ.get('LD_BUGGY') is not None:
                    self._need_continuous_relocations = True
                else:
                    id_section = self._elffile.get_section_by_name('.note.ABI-tag')
                    if id_section:
                        for note in id_section.iter_notes():
                            if note['n_type'] != 'NT_GNU_ABI_TAG':
                                continue
                            abi_tag = note['n_desc']
                            if abi_tag['abi_os'] == 'ELF_NOTE_OS_LINUX' and \
                                    (abi_tag['abi_major'],
                                     abi_tag['abi_minor'],
                                     abi_tag['abi_tiny']) == (2, 6, 32):
                                self._need_continuous_relocations = True
        if self._need_continuous_relocations:
            logging.debug(' * detected buggy loader/old ABI version and BIND_NOW,'\
                            ' keeping relocations continuous...')

        if not self.symtab:
            _arch_dir = 'x86_64-linux-gnu' if self._elffile.header['e_machine'] == 'EM_X86_64' \
                else 'i386-linux-gnu'
            DEBUG_DIR = os.path.join(os.sep, 'usr', 'lib', 'debug', 'lib', _arch_dir)
            BUILDID_DIR = os.path.join(os.sep, 'usr', 'lib', 'debug', '.build-id')
            paths = [os.path.join(DEBUG_DIR, os.path.basename(filename))]
            external_debug_dir = os.environ.get('EXTERNAL_DEBUG_DIR', '')
            if external_debug_dir:
                for debug_path in external_debug_dir.split(':'):
                    paths.insert(0, os.path.join(debug_path, os.path.basename(filename)))
                    paths.insert(1, os.path.join(debug_path, os.path.basename(filename) + '.debug'))

            build_id = None
            id_section = self._elffile.get_section_by_name('.note.gnu.build-id')
            if not id_section:
                logging.debug('search for external symtab: no id_section')
            else:
                for note in id_section.iter_notes():
                    if note['n_type'] != 'NT_GNU_BUILD_ID':
                        continue
                    build_id = note['n_desc']
                    paths.insert(0, os.path.join(BUILDID_DIR,
                                                build_id[:2],
                                                build_id[2:] + '.debug'))
                    external_buildid_dir = os.environ.get('EXTERNAL_BUILDID_DIR', '')
                    if external_buildid_dir:
                        paths.insert(0, os.path.join(external_buildid_dir,
                                                    build_id[:2],
                                                    build_id[2:] + '.debug'))
            for path in paths:
                if not os.path.isfile(path):
                    logging.debug('search for external symtab: no path %s', path)
                    continue
                try:
                    self._external_elf_fd = open(path, 'rb')
                    external_elf = ELFFile(self._external_elf_fd)
                    external_symtab = external_elf.get_section_by_name('.symtab')
                    if external_symtab is None:
                        self._external_elf_fd.close()
                        logging.debug('no .symtab in external file %s', path)
                        continue
                    self.symtab = SectionWrapper(external_symtab, -1, 0)
                    logging.debug('Found external symtab for %s at %s',
                                  filename, path)
                    break
                except OSError as err:
                    logging.debug('Failed to open file at %s: %s', path, err)
                except ELFError as err:
                    logging.debug('Failed to open external ELF file %s for %s: %s',
                                  path, filename, err)
                    self._external_elf_fd.close()

        if not self.symtab and 'USE_DEBUGINFOD' in os.environ and build_id:
            try:
                with DebugInfoD() as debuginfod:
                    logging.debug('Querying debuginfod for debug info')
                    fd, path = debuginfod.find_debuginfo(build_id)
                    if fd > 0:
                        self._external_elf_fd = os.fdopen(fd, 'rb')
                        external_elf = ELFFile(self._external_elf_fd)
                        symtab = external_elf.get_section_by_name('.symtab')
                        if symtab:
                            logging.debug('Found symtab using debuginfod at %s',
                                          path.decode('utf-8'))
                            self.symtab = SectionWrapper(symtab, -1, 0)
            except (ELFError, OSError, FileNotFoundError) as e:
                logging.debug('libdebuginfod query failed: %s', e)

        if self.symtab:
            logging.debug('* found a .symtab section for %s', filename)

        # fallback if section headers have been stripped from the binary
        if self.dynsym is None and self.symtab is None:
            logging.info("* No section headers found in ELF, fallback to dynamic segment!")
            for seg in self._elffile.iter_segments():
                if isinstance(seg, DynamicSegment):

                    # try to build symtab section from dynamic segment information
                    size = seg.num_symbols() * seg.elfstructs.Elf_Sym.sizeof()
                    _, offset = seg.get_table_offset('DT_SYMTAB')
                    self.dynsym = SectionWrapper(self._build_symtab_section('.dynsym', offset, size,
                                                                            seg.elfstructs.Elf_Sym.sizeof(),
                                                                            seg._get_stringtable()),
                                                 -1, 0)
                    logging.debug('* Found \'DYNSYM\' section!')

                    # search for all supported sections and build section object with needed entries
                    rel_plt_off = rel_plt_size = rel_dyn_off = rel_dyn_size = 0
                    for tag in seg.iter_tags():
                        if tag['d_tag'] == "DT_GNU_HASH":
                            logging.debug('* Found \'GNU_HASH\' section!')
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._gnu_hash = SectionWrapper((self._build_section('.gnu.hash', offset, -1, 0, 0)), -1, 0)
                        if tag['d_tag'] == "DT_HASH":
                            logging.debug('* Found \'HASH\' section!')
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._elf_hash = SectionWrapper((self._build_section('.hash', offset, -1, 0, 0)), -1, 0)
                        if tag['d_tag'] == "DT_VERSYM":
                            logging.debug('* Found \'GNU_VERSION\' section!')
                            size = seg.num_symbols() * 2
                            _, offset = seg.get_table_offset(tag['d_tag'])
                            self._gnu_version = SectionWrapper(self._build_section('.gnu.version', offset, size, 2, 0), -1, 0)

                        if tag['d_tag'] == "DT_JMPREL":
                            _, rel_plt_off = seg.get_table_offset(tag['d_tag'])
                        if tag['d_tag'] == "DT_PLTRELSZ":
                            rel_plt_size = tag['d_val']

                        if tag['d_tag'] == "DT_RELA" or tag['d_tag'] == "DT_REL":
                            _, rel_dyn_off = seg.get_table_offset(tag['d_tag'])
                        if tag['d_tag'] == "DT_RELASZ" or tag['d_tag'] == "DT_RELSZ":
                            rel_dyn_size = tag['d_val']

                    ent_size = seg.elfstructs.Elf_Rela.sizeof() if (self._elffile.header['e_machine'] == 'EM_X86_64') else seg.elfstructs.Elf_Rel.sizeof()
                    sec_name = '.rela.' if (self._elffile.header['e_machine'] == 'EM_X86_64') else '.rel.'
                    sec_out_name = 'RELA_' if (self._elffile.header['e_machine'] == 'EM_X86_64') else 'REL_'
                    sec_type = 'SHT_RELA' if (self._elffile.header['e_machine'] == 'EM_X86_64') else 'SHT_REL'

                    if rel_plt_off != 0 and rel_plt_size != 0:
                        logging.debug('* Found \'%sPLT\' section!', sec_out_name)
                        self._rel_plt = SectionWrapper(self._build_relocation_section(sec_name + 'plt', rel_plt_off, rel_plt_size, ent_size, sec_type), -1, 0)
                    if rel_dyn_off != 0 and rel_dyn_size != 0:
                        logging.debug('* Found \'%sDYN\' section!', sec_out_name)
                        self._rel_dyn = SectionWrapper(self._build_relocation_section(sec_name + 'dyn', rel_dyn_off, rel_dyn_size, ent_size, sec_type), -1, 0)


    def __del__(self):
        self._f.close()
        if self._external_elf_fd:
            self._external_elf_fd.close()

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
        header = {'sh_name': name, 'sh_type': shtype, 'sh_flags': 0,
                  'sh_addr': 0, 'sh_offset': off, 'sh_size': size, 'sh_link': 0,
                  'sh_info': 0, 'sh_addralign': 0, 'sh_entsize': entsize}

        return header

    def _set_section_attribute(self, section, attribute, value, subtract_from_orig=False):
        # can't change section header f no header in elffile
        if section.index == -1:
            return
        machine_type = self._elffile.header['e_machine']
        if attribute == 'sh_size':
            member_offset, member_size = (32, 8) if machine_type == 'EM_X86_64' else (20, 4)
        elif attribute == 'sh_info':
            member_offset, member_size = (44, 4) if machine_type == 'EM_X86_64' else (28, 4)
        else:
            raise Exception('Trying to set invalid section attribute {}'.format(attribute))

        head_entsize = self._elffile['e_shentsize']
        off_to_head = self._elffile['e_shoff'] + (head_entsize * section.index)

        self._f.seek(off_to_head + member_offset)
        old_bytes = self._f.read(member_size)
        old_value = int.from_bytes(old_bytes, self._byteorder, signed=False)
        if old_value < value:
            raise Exception('Size of section broken! Section: {}'.format(section.section.name)
                            + ' Size: {}'.format(value))
        if subtract_from_orig:
            new_value = old_value - value
        else:
            new_value = value
        self._f.seek(off_to_head + member_offset)
        self._f.write(new_value.to_bytes(member_size, self._byteorder))
        section.section.header[attribute] = new_value

    def _set_section_size(self, section, value, subtract_from_orig=False):
        self._set_section_attribute(section, 'sh_size', value, subtract_from_orig)

    '''
    Function:   _change_section_size
    Parameter:  section = Tuple with section object and index (object, index)
                size    = size in Bytes

    Description: Decreases the size of the given section in its header by 'size' bytes
    '''
    def _change_section_size(self, section, amount):
        self._set_section_size(section, amount, subtract_from_orig=True)

    def _set_section_info(self, section, value, subtract_from_orig=False):
        self._set_section_attribute(section, 'sh_info', value, subtract_from_orig)

    def _write_dynamic_tag(self, target_tag, value, subtract_from_orig=False):
        dynamic_section = self._dynamic.section
        found_tag = [idx for idx, tag in enumerate(dynamic_section.iter_tags()) if tag['d_tag'] == target_tag]
        if not found_tag:
            return
        f_off = dynamic_section._offset + found_tag[0] * dynamic_section._tagsize
        self._f.seek(f_off)
        raw_val = self._f.read(dynamic_section._tagsize)
        if dynamic_section._tagsize == 8:
            struct_string = self._endianness + 'iI'
        else:
            struct_string = self._endianness + 'qQ'
        tagno, old_val = struct.unpack(struct_string, raw_val)
        new_val = old_val - value if subtract_from_orig else value
        new_raw_val = struct.pack(struct_string, tagno, new_val)
        self._f.seek(f_off)
        self._f.write(new_raw_val)

    def _shrink_dynamic_tag(self, target_tag, amount):
        return self._write_dynamic_tag(target_tag, amount, subtract_from_orig=True)

    def _reloc_get_addend_RELA(self, reloc):
        return reloc.entry['r_addend']

    def _reloc_set_addend_RELA(self, reloc, value):
        reloc.entry['r_addend'] = value

    def _reloc_get_addend_REL(self, reloc):
        target = reloc['r_offset']
        off = next(self._elffile.address_offsets(target))
        self._f.seek(off)
        addend = struct.unpack(self._endianness + 'I', self._f.read(4))[0]
        return addend

    def _reloc_set_addend_REL(self, reloc, value):
        target = reloc['r_offset']
        off = next(self._elffile.address_offsets(target))
        self._f.seek(off)
        addend = struct.pack(self._endianness + 'I', value)
        self._f.write(addend)

    def _batch_remove_relocs(self, symbol_list, section, push=False, is_symtab=False):
        if section is None:
            return

        if section.section.is_RELA():
            ent_size = 24 # Elf64_rela struct size, x64 always rela?
            getter_addend = self._reloc_get_addend_RELA
            setter_addend = self._reloc_set_addend_RELA
        else:
            ent_size = 8 # Elf32_rel struct size, x86 always rel
            getter_addend = self._reloc_get_addend_REL
            setter_addend = self._reloc_set_addend_REL

        # Sort the relocation table by the symbol indices. This allows faster
        # rewriting when we actually delete entries from the table, see the
        # comments below.
        orig_reloc_list = list(section.section.iter_relocations())
        relocs = [(reloc, reloc.entry['r_info_sym'], getter_addend(reloc)) \
                  for reloc in orig_reloc_list]
        relocs = sorted(relocs, key=lambda x: (x[1], x[2]))
        sort_keys = [(x[1], x[2]) for x in relocs]

        # Sets for quicker lookup if we really need to iterate over the
        # relocations, relocations now sorted by symbol number and addend
        reloc_list, sym_nrs, sym_addrs = zip(*relocs)
        reloc_list, sym_nrs, sym_addrs = list(reloc_list), set(sym_nrs), set(sym_addrs)

        logging.debug(' * searching relocations to remove from %s', section.section.name)
        removed = 0
        for symbol in symbol_list:
            # If the symbol to be removed is neither referenced via its address
            # (for both .symtab and .dynsym) nor by its index (only in case of
            # .dynsym), we don't need to iterate the relocation table at all.
            if symbol.value not in sym_addrs:
                if is_symtab:
                    continue
                if symbol.index not in sym_nrs:
                    continue
            removed += self._edit_rel_sect(reloc_list, sort_keys, symbol.index,
                                           symbol.value, getter_addend,
                                           setter_addend, push, is_symtab)
            if not is_symtab:
                sym_nrs.discard(symbol.index)
            sym_addrs.discard(symbol.value)

        # For all removed symbols, we need to fix up the symbol table indices
        # of all 'later' symbols. Here, we use that the relocations _and_ the
        # symbols to be removed are sorted by their indices: we only need to
        # rewrite entries in the relocation table with higher indices than the
        # index of the removed symbol, and those are now always at the back of
        # the relocation list). By starting with the highest symbol table index
        # first (as given in symbol_list), we only need one iteration over the
        # relocation list to fix up all indices. Note that this must only be
        # done for the .dynsym section and not if we delete relocations
        # referring to local functions from .symtab (as the indices always
        # reference symbols in .dynsym)
        logging.debug(' * fixing up remaining symbol indices')
        if not is_symtab:
            cur_symbol_idx = 0
            cur_symbol = symbol_list[cur_symbol_idx]
            cur_reloc_idx = len(reloc_list) - 1
            num_earlier_removed_symbols = len(symbol_list)
            # The relocation list is sorted from low to high symbol indices so
            # we need to start at the back.
            while cur_reloc_idx >= 0:
                reloc = reloc_list[cur_reloc_idx]
                r_info_sym = reloc.entry['r_info_sym']
                # If we are working on a relocation section with no
                # intentionally zeroed entries and we have reached the
                # relocations without symbol indices, we're done.
                if r_info_sym == 0:
                    if push:
                        break
                # If we found a relocation that references a symbol with a
                # lower index than the currently looked at symbol, we need to
                # 'skip over' the removed symbol and account for it in the
                # number subtracted from the following relocations
                elif r_info_sym <= cur_symbol.index:
                    num_earlier_removed_symbols -= 1
                    # There are no earlier symbols left, we're done
                    if num_earlier_removed_symbols == 0:
                        break
                    cur_symbol_idx += 1
                    cur_symbol = symbol_list[cur_symbol_idx]
                    continue
                # Fix the current relocation by subtracting the difference in
                # symbol indices caused by the removal of functions with lower
                # indices in the original .dynsym. If the symbol was zero
                # already (for example if it was zeroed intentionally), leave
                # it as it is
                if r_info_sym == 0:
                    new_sym = 0
                else:
                    new_sym = r_info_sym - num_earlier_removed_symbols
                old_type = reloc.entry['r_info_type']
                if ent_size == 8:
                    reloc.entry['r_info'] = new_sym << 8 | (old_type & 0xFF)
                else:
                    reloc.entry['r_info'] = new_sym << 32 | (old_type & 0xFFFFFFFF)
                reloc.entry['r_info_sym'] = new_sym
                cur_reloc_idx -= 1

        # restore old order of relocation list - not sure if we're really
        # required to do this but it doesn't hurt performance too badly
        logging.debug(' * restoring original order of relocations')
        new_reloc_list = []
        lookup_dict = {reloc.entry['r_offset']: reloc for reloc in reloc_list}
        for orig_reloc in orig_reloc_list:
            new_reloc = lookup_dict.get(orig_reloc.entry['r_offset'], None)
            if new_reloc:
                new_reloc_list.append(new_reloc)

        reloc_list = new_reloc_list

        # Write whole section out at once
        logging.debug(' * writing relocation section %s to file', section.section.name)

        # Write all entries out
        self._f.seek(section.section.header['sh_offset'])

        relocs_bytes = []
        for reloc in reloc_list:
            if ent_size == 24:
                relocs_bytes.append(struct.pack(self._endianness + 'QqQ', reloc.entry['r_offset'],
                                                reloc.entry['r_info'], reloc.entry['r_addend']))
            else:
                relocs_bytes.append(struct.pack(self._endianness + 'Ii', reloc.entry['r_offset'],
                                                reloc.entry['r_info']))

        # Write new entries and zero the remainder of the old section. If we
        # need to keep the relocation section size constant but still push
        # entries forward, repeat the last relocation to fill the section.
        if self._need_continuous_relocations:
            last_reloc = relocs_bytes[-1]
            fill_bytes = removed * last_reloc
        else:
            fill_bytes = (ent_size * removed) * b'\00'
        self._f.write(b''.join(relocs_bytes) + fill_bytes)

        # Change the size in the section header
        if not self._need_continuous_relocations:
            self._change_section_size(section, ent_size * removed)
        # the following is needed in order to lower the number of relocations
        # returned via iter_relocations() -> uses num_relocations() -> uses
        # _size to calculate the number
        if not self._need_continuous_relocations:
            section.section._size -= (ent_size * removed)

        if push:
            # Shrink the total number of relocation entries and (optionally)
            # the number of R_XX_RELATIVE relocations in the DYNAMIC segment
            if section.section.is_RELA():
                if not self._need_continuous_relocations:
                    self._shrink_dynamic_tag('DT_RELASZ', ent_size * removed)
                relacount = len([reloc for reloc in reloc_list \
                                if reloc['r_info_type'] == ENUM_RELOC_TYPE_x64['R_X86_64_RELATIVE']])
                self._write_dynamic_tag('DT_RELACOUNT', relacount)
            else:
                if not self._need_continuous_relocations:
                    self._shrink_dynamic_tag('DT_RELSZ', ent_size * removed)
                relcount = len([reloc for reloc in reloc_list \
                                if reloc['r_info_type'] == ENUM_RELOC_TYPE_i386['R_386_RELATIVE']])
                self._write_dynamic_tag('DT_RELCOUNT', relcount)

        logging.debug(' * done, removed %d relocations!', removed)

    '''
    Function:   _edit_rel_sect
    Parameter:  section = Tuple with section object and index (object, index)
                sym_nr  = index of removed entry in dynsym

    Description: adapts the entries of the given relocation section to the changed dynsym
    '''
    def _edit_rel_sect(self, reloc_list, sort_keys, sym_nr, sym_addr, getter_addend,
                       setter_addend, push=False, is_symtab=False):
        removed = 0
        # Search the sorted list of relocations for a R_XX_RELATIVE relocation
        # with the address sym_addr
        cur_idx = bisect.bisect_left(sort_keys, (0, sym_addr))
        # If there is no such relocation, skip forward to the first relocation
        # with the symbol index we're removing.
        if not is_symtab and sort_keys[cur_idx][1] != sym_addr:
            cur_idx = bisect.bisect_left(sort_keys, (sym_nr, 0), cur_idx)
        list_len = len(reloc_list)
        logging.debug('  * searching relocations for index %x/address %x', sym_nr, sym_addr)
        while cur_idx < list_len:
            reloc = reloc_list[cur_idx]
            r_info_sym = reloc.entry['r_info_sym']
            if (not is_symtab and r_info_sym == sym_nr) or getter_addend(reloc) == sym_addr:
                logging.debug('   * found: relocation offset = %x, removing', reloc.entry['r_offset'])
                if push:
                    reloc_list.pop(cur_idx)
                    sort_keys.pop(cur_idx)
                    removed += 1
                    list_len -= 1
                    continue
                else:
                    reloc.entry['r_info_sym'] = 0
                    setter_addend(reloc, 0)
            # If we're processing a .symtab, we can only look at R_XX_RELATIVE
            # relocations and thus have to stop when the relocation entry
            # references a symbol that's part of .dynsym. Additionally, we can
            # stop processing when we reach an addend higher than our currently
            # looked at symbol as the table is sorted by the addend as a second
            # key.
            elif is_symtab and (getter_addend(reloc) > sym_addr or r_info_sym > 0):
                break
            # This break works because the relocation entries are sorted and
            # R_XX_RELATIVE relocations (which might have their r_addend field
            # set to the address of our symbol) are required to have 0 as their
            # symbol table index (and thus always come first).
            elif r_info_sym > sym_nr:
                break
            # If we're dealing with symbol indices, search forward for the next
            # entry with the corresponding symbol_number. We will end up in this
            # case when all R_XX_relative entries with (0, sym_addr) have been
            # removed from the relocation table.
            elif not is_symtab:
                cur_idx = bisect.bisect_left(sort_keys, (sym_nr, 0), cur_idx)

            cur_idx += 1

        return removed

    '''
    Function:   _batch_remove_gnu_versions
    Parameter:  symbol_list      = the list of symbols that are removed from the
                                   dynsym table
                orig_dynsym_size = the original number of symbols in the dynsym
                                   section

    Description: rewrites the '.gnu.version' section by removing all symbols
                 from symbol_list
    '''
    def _batch_remove_gnu_versions(self, symbol_list, orig_dynsym_size):
        if self._gnu_version is None:
            return

        ent_size = 2
        # Read the version section as a whole and interpret as a list of
        # ElfXX_Half integers
        self._f.seek(self._gnu_version.section.header['sh_offset'])
        section_bytes = self._f.read(orig_dynsym_size * ent_size)
        fmt_str = self._endianness + str(orig_dynsym_size) + 'H'
        versions = list(struct.unpack(fmt_str, section_bytes))

        for symbol in symbol_list:
            versions.pop(symbol.index)

        # Build and write the new versions section, zero out rest of the section
        fmt_str = self._endianness + str(len(versions)) + 'H'
        new_section_bytes = struct.pack(fmt_str, *versions)
        self._f.seek(self._gnu_version.section.header['sh_offset'])
        self._f.write(new_section_bytes + \
                      b'\00' * ((orig_dynsym_size - len(versions)) * ent_size))

        self._change_section_size(self._gnu_version, ent_size * len(symbol_list))

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
            if g != 0:
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
    Helper function to test the consitency of the standard hash section
    '''
    # temporary test function
    def test_hash_section(self):
        if self._elf_hash is not None:
            sect = ELFHashTable(self._elffile,
                                self._elf_hash.section.header['sh_offset'],
                                self.dynsym.section)
            # print hash section
            #for i in range (0, sect.params['nchains']):
            #    print(self.dynsym.section.get_symbol(i).name)

            # find every symbol in hash table
            for i in range(1, self.dynsym.section.num_symbols()):
                sym = self.dynsym.section.get_symbol(i)
                name = sym.name
                #print("Check hash of symbol: " + name)
                sym_hash = self._elfhash(name)
                bucket = sym_hash % sect.params['nbuckets']
                cur_ptr = sect.params['buckets'][bucket]
                found = 0
                while cur_ptr != 0:
                    if self.dynsym.section.get_symbol(cur_ptr).name == name:
                        #print("     Found!")
                        found = 1
                        break
                    cur_ptr = sect.params['chains'][cur_ptr]
                if found == 0:
                    raise Exception("Symbol {} not found in bucket!!! Hash Section broken!".format(name))

    def _calc_nbuckets(self, n_hashes):
        options = [1, 3, 17, 37, 67, 97, 131, 197, 263, 521, 1031, 2053, 4099,
                   8209, 16411, 32771, 65537, 131101, 262147]
        ins_point = bisect.bisect(options, n_hashes)
        return options[ins_point-1]

    '''
    Function:   _recreate_elf_hash
    Parameter:  dynsym         = the already modified dynsym section (symbols
                                 have already been removed).
                n_removed_syms = the number of symbols that were removed from
                                 the dynsym table

    Description: creates a new '.hash' section based on the rewritten dynsym
                 and writes it to the target file
    '''
    def _recreate_elf_hash(self, dynsym, n_removed_syms):
        if self._elf_hash is None:
            return

        sect = ELFHashTable(self._elffile,
                            self._elf_hash.section.header['sh_offset'],
                            dynsym.section)
        params = {'nbuckets': sect.params['nbuckets'],
                  'nchains': sect.params['nchains'],
                  'buckets': sect.params['buckets'],
                  'chains': sect.params['chains']}

        # Gaps in new_buckets and new_chains will be filled with 0 when writing
        # the contents out, indicating either no symbol in the current bucket
        # or the end of a chain
        new_buckets = {}
        new_chains = {}

        params['nchains'] -= n_removed_syms
        params['nbuckets'] = self._calc_nbuckets(params['nchains'])

        for idx, symbol in enumerate(dynsym.section.iter_symbols()):
            bucket = self._elfhash(symbol.name) % params['nbuckets']
            # Insert current symbol as the first one (in the corresponding
            # bucket entry) and set the link to the previous first symbol by
            # setting the chain entry to the current value from buckets.
            new_chains[idx] = new_buckets.get(bucket, 0)
            new_buckets[bucket] = idx

        # Zero out old hash table
        self._f.seek(self._elf_hash.section.header['sh_offset'])
        self._f.write(b'\00' * self._elf_hash.section.header['sh_size'])

        # write to file
        #  - nbucket
        self._f.seek(self._elf_hash.section.header['sh_offset'])
        self._f.write(params['nbuckets'].to_bytes(4, self._byteorder))
        #  - nchain
        self._f.seek(self._elf_hash.section.header['sh_offset'] + 4)
        self._f.write(params['nchains'].to_bytes(4, self._byteorder))

        # - buckets
        out = b''.join(new_buckets.get(i, 0).to_bytes(4, self._byteorder) \
                       for i in range(0, params['nbuckets']))
        self._f.write(out)

        # - chains
        out = b''.join(new_chains.get(i, 0).to_bytes(4, self._byteorder) \
                       for i in range(0, params['nchains']))
        self._f.write(out)

        self._set_section_size(self._elf_hash,
                               (2 + params['nchains'] + params['nbuckets']) * 4)

    def _batch_remove_gnu_hashtable(self, symbol_list, dynsym_size):
        if self._gnu_hash is None:
            return

        sh_offset = self._gnu_hash.section.header['sh_offset']
        sect = GNUHashTable(self._elffile, sh_offset, self.dynsym.section)
        params = {'nbuckets': sect.params['nbuckets'],
                  'symoffset': sect.params['symoffset'],
                  'bloom_size': sect.params['bloom_size'],
                  'bloom_entry_size': 4 if self._elffile.header['e_machine'] == 'EM_386' else 8,
                  'buckets': list(sect.params['buckets'])}

        bucket_start = sh_offset + 4 * 4 + params['bloom_size'] * params['bloom_entry_size']
        chain_start = bucket_start + 4 * params['nbuckets']

        self._f.seek(chain_start)
        nchains = dynsym_size - params['symoffset']
        params['chains'] = list(struct.unpack(self._endianness + str(nchains) + 'I',
                                              self._f.read(nchains * 4)))

        func_hashes = [self._gnuhash(symbol.name) for symbol in symbol_list]
        func_buckets = [func_hash % params['nbuckets'] for func_hash in func_hashes]
        if sorted(func_buckets, reverse=True) != func_buckets:
            raise Exception("bucket numbers of symbols to be deleted are not sorted!")

        for idx, symbol in enumerate(symbol_list):
            logging.debug('\t%s: adjust gnu_hash_section, hash = %x bucket = %d',
                          symbol.name, func_hashes[idx], func_buckets[idx])
            self._edit_gnu_hashtable(symbol.index, func_hashes[idx], params)

        # Fix bucket indices accounting for deleted symbols. Start from the
        # back as symbols (and therefore also their buckets) are sorted in
        # descending order: for later buckets, we need to subtract more from
        # the bucket start indices as more symbols have been removed before the
        # currently checked one.
        max_idx = params['nbuckets'] - 1
        cur_sym = 0
        num_earlier_removed_symbols = len(symbol_list)
        while max_idx >= 0:
            while num_earlier_removed_symbols > 0 and func_buckets[cur_sym] >= max_idx:
                cur_sym += 1
                num_earlier_removed_symbols -= 1
            if num_earlier_removed_symbols == 0:
                break
            params['buckets'][max_idx] = max(0, params['buckets'][max_idx] - num_earlier_removed_symbols)
            max_idx -= 1

        # Set last entries in buckets array to 0 if all symbols for the last
        # buckets have been deleted from the file.
        max_idx = params['nbuckets'] - 1
        while params['buckets'][max_idx] == dynsym_size - len(symbol_list):
            params['buckets'][max_idx] = 0
            max_idx -= 1

        # Write out buckets
        self._f.seek(bucket_start)
        buckets_bytes = struct.pack(self._endianness + str(params['nbuckets']) + 'I',
                                    *params['buckets'])
        self._f.write(buckets_bytes)
        # We're automatically at chain_start here, so write the new chains
        # array and zero the remaining old contents
        chains_bytes = struct.pack(self._endianness + str(len(params['chains'])) + 'I',
                                   *params['chains'])
        self._f.write(chains_bytes + (nchains - len(params['chains'])) * 4 * b'\00')

        self._change_section_size(self._gnu_hash, len(symbol_list) * 4)

        #check_hash_table = GNUHashTable(self._elffile,
        #                                self._gnu_hash.section['sh_offset'],
        #                                self.dynsym.section)
        #for symbol in self.dynsym.section.iter_symbols():
        #    if symbol.entry['st_shndx'] == 'SHN_UNDEF':
        #        continue
        #    retval = check_hash_table.get_symbol(symbol.name)
        #    if retval is None:
        #        raise(Exception, 'symbol {} not found in hashtable!'.format(symbol.name))


    '''
    Function:   _edit_gnu_hashtable
    Parameter:  dynsym_nr     = nr of the given symbol in the dynsym table
                func_hash     = the hash of the symbol to be removed
                params        = the parameters of the GNU hash table

    Description: removes the given Symbol from the '.gnu.hash' section
    '''
    def _edit_gnu_hashtable(self, dynsym_nr, func_hash, params):
        ### remove deleted entry from bucket ###
        # check hash
        sym_nr = dynsym_nr - params['symoffset']
        if sym_nr < 0:
            raise Exception('Function index out of bounds for gnu_hash_section! Index: {}'.format(sym_nr))

        bucket_hash = params['chains'][sym_nr]
        # if this happens, sth on the library or hash function is broken!
        if (bucket_hash & ~0x1) != (func_hash & ~0x1):
            raise Exception('calculated hash: {:x}, read hash: {:x}'.format(func_hash, bucket_hash))

        # copy all entrys afterwards up by one
        params['chains'].pop(sym_nr)

        # if last bit is set for deleted symbol...
        if (bucket_hash & 0x1) == 1:
            bucket = func_hash % params['nbuckets']
            if sym_nr != 0:
                # ... and the previous chain entry is also terminating a chain,
                # mark the bucket as empty.
                if params['chains'][sym_nr - 1] & 0x1 == 1:
                    params['buckets'][bucket] = 0
                # otherwise, mark the previous entry as the end of the chain.
                else:
                    params['chains'][sym_nr - 1] |= 0x00000001
            # If we removed the first symbol and it was a terminating entry,
            # we can also mark the first bucket as empty.
            else:
                params['buckets'][bucket] = 0

    # Fix the sh_info field of the corresponding section header table entry.
    # For symbol tables, sh_info must be set to the index of the first non-local
    # symbol in the table.
    def _fix_sh_info(self, section, section_entries):
        first_nonlocal = 0
        sh_info_offset = 4 if self._elffile.header['e_machine'] == 'EM_X86_64' else 12
        for idx, entry in enumerate(section_entries):
            # #define ELF32_ST_BIND(info)          ((info) >> 4)
            # #define ELF64_ST_BIND(info)          ((info) >> 4)
            current_bind = entry[sh_info_offset:sh_info_offset+1][0] >> 4
            if current_bind != 0:
                first_nonlocal = idx
                break
        self._set_section_info(section, first_nonlocal)

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
        if section is None:
            raise Exception('Section not available!')

        if not collection:
            return 0

        logging.info('* removing symbols from symbol table (%s)', section.section.name)
        # sort list by offset in symbol table
        # otherwise the index would be wrong after one Element was removed
        sorted_list = sorted(collection, reverse=True, key=lambda x: x.index)

        removed = 0
        sh_offset = section.section.header['sh_offset']
        sh_size = section.section.header['sh_size']
        sh_entsize = section.section.header['sh_entsize']
        max_entrys = (sh_size // sh_entsize)
        original_num_entries = max_entrys

        if section.index != -1:
            self._f.seek(sh_offset)
            section_bytes = self._f.read(sh_size)
            section_entries = [section_bytes[i:i+sh_entsize] for i in range(0, len(section_bytes),
                                                                            sh_entsize)]
        else:
            section_entries = []

        for symbol_t in sorted_list:
            # check if section was changed between the collection and removal of Symbols
            if symbol_t.sec_version != section.version:
                raise Exception('symbol_collection was generated for older revision of ' \
                                + section.section.name)
            #### Delete Symbol Table entry ####
            logging.debug(' * %s: deleting table entry', symbol_t.name)
            if section.index != -1:
                section_entries.pop(symbol_t.index)

            #### Overwrite function with zeros ####
            if overwrite and section.index != -1:
                if symbol_t.value != 0 and symbol_t.size != 0:
                    logging.debug('  * overwriting text segment with 0xcc')
                    self._f.seek(symbol_t.value)
                    self._f.write(b'\xcc' * symbol_t.size)
            removed += 1
            max_entrys -= 1

        # Only write to file if the section is actually part of the file
        if section.index != -1:
            # Write new symbol table and zero out the rest of the old contents
            self._f.seek(sh_offset)
            self._f.write(b''.join(section_entries) + (sh_entsize * removed) * b'\00')

        self._change_section_size(section, removed * sh_entsize)
        self._fix_sh_info(section, section_entries)
        section = SectionWrapper(section.section, section.index, section.version + 1)

        #TODO: check if symtab relocation removal really works, we didnt do
        # this so far.
        logging.info('* adapting dynamic relocation entries')
        self._batch_remove_relocs(sorted_list, self._rel_dyn, push=True,
                                  is_symtab=(section.section.name == '.symtab'))
        if section.section.name == '.dynsym':
            self.dynsym = section
            logging.info('* adapting PLT relocation entries')
            self._batch_remove_relocs(sorted_list, self._rel_plt)
            logging.info('* rebuilding ELF-style hashes')
            self._recreate_elf_hash(self.dynsym, removed)
            logging.info('* adapting symbol versions')
            self._batch_remove_gnu_versions(sorted_list, original_num_entries)
            logging.info('* adapting GNU-style hashes')
            self._batch_remove_gnu_hashtable(sorted_list, original_num_entries)

        logging.info('* ... done!')
        return removed

    '''
    Function:   collect_symbols_by_name (and -_by_address)
    Parameter:  section     = symbol table to search in (self.symtab, self.dynsym)
                symbol_list = list of symbol names to be collected
                complement  = Boolean, True: all symbols except given list are collected
    Returns:    collection of matching Symbols in given symboltable
                NOTE: collection contains indices of Symbols -> all collections are invalidated
                      after symboltable changes.

    Description: Gathers a list of symbols which are described by the symbol
                 or address list given as the parameter
    '''
    def collect_symbols_by_name(self, section, symbol_list, complement=False):
        logging.info('* searching symbols (by name) to delete in section: %s',
                     section.section.name)

        #### Search for function in Symbol Table ####
        entry_cnt = -1
        found_symbols = []

        for symbol in section.section.iter_symbols():
            entry_cnt += 1
            if symbol.name in self._blacklist:
                continue
            if (complement and symbol.name not in symbol_list) or \
                    (not complement and symbol.name in symbol_list):
                start_address = symbol.entry['st_value']
                size = symbol.entry['st_size']

                # Symbol not a function -> next
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                # add all symbols to remove to the return list
                # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                found_symbols.append(SymbolWrapper(symbol.name, entry_cnt,
                                                   start_address, size,
                                                   section.version))
        return found_symbols

    def collect_symbols_by_address(self, section, address_list, complement=False):
        logging.info('* searching symbols (by address) to delete in section: %s', section.section.name)

        #### Search for function in Symbol Table ####
        entry_cnt = -1
        found_symbols = []

        for symbol in section.section.iter_symbols():
            entry_cnt += 1
            if symbol.name in self._blacklist:
                continue
            # fix for section from dynamic segment
            start_address = symbol.entry['st_value']
            if (complement and start_address not in address_list) or \
                    (not complement and start_address in address_list):
                size = symbol.entry['st_size']
                # Symbol not a function -> next
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                # add all symbols to remove to the return list
                # format (name, offset_in_table, start_of_code, size_of_code, section_revision)
                found_symbols.append(SymbolWrapper(symbol.name, entry_cnt,
                                                   start_address, size,
                                                   section.version))
        return found_symbols

    '''
    Function:   overwrite local functions
    Parameter:  func_tuple_list = list of tupels with address and size information for to be removed local functions

    Description: overwrites the given functions in the text segment and removes the entries from symtab if present
    '''
    def overwrite_local_functions(self, func_tuple_list):
        logging.debug('* overwriting local functions')
        for start, size in func_tuple_list:
            if size == 0:
                continue
            #### Overwrite function with null bytes ####
            logging.debug('  * %x: overwriting text segment of local function', start)
            self._f.seek(start)
            self._f.write(b'\xCC' * size)

        if self.symtab is not None:
            addr = set(start for start, size in func_tuple_list)
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
        if full:
            if local is not None:
                print('Local Functions: ' + str(len(local)))
                line = "{0:<10} | {1:<6}"
                print(line.format("Address", "Size"))
                print(16 * '-')
                for func in local:
                    print(line.format(func[0], func[1]))

            maxlen = 0
            for x in collection:
                if len(x.name) > maxlen:
                    maxlen = len(x.name)
            print('Symbols in collection: ' + str(len(collection)))
            line = "{0:<" + str(maxlen) + "} | {1:<8} | {2:<10} | {3:<6} | {4:<6}"
            print(line.format("Name", "Offset", "StartAddr", "Size", "Rev."))
            print((maxlen + 40) * '-')
            for sym in collection:
                print(line.format(sym.name, sym.index, sym.value, hex(sym.size), sym.sec_version))
        else:
            size_of_text = 0
            for section in self._elffile.iter_sections():
                if section.name == '.text':
                    size_of_text = section["sh_size"]

            # create dict for unique address values
            addr_dict = {}
            for ent in collection:
                addr_dict[ent.value] = ent.size

            if local:
                for start, size in local:
                    addr_dict[start] = size

            total_b_rem = 0
            for _, v in addr_dict.items():
                #print(sym.name + " ", end="", flush=True)
                total_b_rem += v

            dynsym_entrys = (self.dynsym.section.header['sh_size'] // self.dynsym.section.header['sh_entsize'])

            print("Total number of symbols in dynsym: " + str(dynsym_entrys))
            print("    Nr of symbols to remove: " + str(len(collection)))
            if local:
                print("    Nr of local functions to remove: " + str(len(local)))
            if size_of_text != 0:
                print("Total size of text Segment: " + str(size_of_text))
                print("    Nr of bytes overwritten: " + str(total_b_rem))
                print("    Percentage of code overwritte: " + str((total_b_rem / size_of_text) * 100))
            else:
                print("Size of text Segment not given in section header")

            #print(" & " + str(dynsym_entrys) + " & " + str(len(collection)) + " & " + str(len(local)) + " & " + str(size_of_text) + " & " + str(total_b_rem) + " & " + str((total_b_rem / size_of_text) * 100) + "\\% \\\\")

    '''
    helper functions
    '''
    def get_collection_addr(self, collection, local=None):
        # create dictionary to ensure no double values
        addr_dict = {}
        for ent in collection:
            addr_dict[ent.value] = ent.size
        if local:
            for func in local:
                addr_dict[func[0]] = func[1]

        # sort by address
        return collections.OrderedDict(sorted(addr_dict.items()))

    def print_collection_addr(self, collection, local=None):
        ordered_collection = self.get_collection_addr(collection, local)
        for k, v in ordered_collection.items():
            print(str(k) + " " + str(v))

    def get_collection_names(self, collection):
        symbols = []
        for sym in collection:
            symbols.append(sym.name)
        return symbols

    def fixup_function_ranges(self, collection, ranges, lib):
        for symbol in collection:
            if symbol.value in ranges and ranges[symbol.value] != symbol.size:
                new_size = ranges[symbol.value]
                logging.debug('fix size for %s:%x: %d->%d', lib.fullname,
                                                            symbol.value,
                                                            symbol.size,
                                                            new_size)
                symbol.size = new_size

    def get_keep_list(self, total_size, collection, local=None):
        addrs = self.get_collection_addr(collection, local)
        # Generate ranges to keep in the output file, starting from the
        # beginning of the file. Gaps between sections are parsed by
        # shrinkelf itself.
        ranges = []
        ranges.append([0])
        index = 0
        for start, size in addrs.items():
            # addrs contains removed functions so the end of the range
            # to keep is the start of the removed function and the beginning
            # of the next range to keep is the end of the removed function
            end = start
            next_start = start + size
            # if the ranges would be immediately adjacent, merge them by
            # skipping the update of the previous and creation of a new
            # range
            if next_start == end:
                continue
            ranges[index].append(end)
            ranges.append([next_start])
            index += 1
        ranges[index].append(total_size)
        return ranges
