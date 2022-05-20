import os
import unittest
import shutil

from elftools.elf.elffile import ELFFile
from elfremove.elfremove import ELFRemove

INPUT_FILE_FOLDER = os.path.join('test', 'test_files')
INPUT_FILE_PATH = os.path.join(INPUT_FILE_FOLDER, 'libtest.so')
TAILORED_FILE_PATH = os.path.join(INPUT_FILE_FOLDER, 'libtest.tailored.so')

class TestELFRemove(unittest.TestCase):

    def _get_defined_symbols(self, elf):
        dynsym = elf.get_section_by_name('.dynsym')
        symbols = list(sym for sym in dynsym.iter_symbols() if sym['st_shndx'] != 'SHN_UNDEF')
        return dynsym, symbols

    def test_remove_one(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, TAILORED_FILE_PATH)
        elfrem = ELFRemove(TAILORED_FILE_PATH)

        to_remove = ['addtest']
        elfrem.collect_symbols_in_dynsym(names=to_remove)
        if elfrem.symtab is not None:
            elfrem.collect_symbols_in_symtab(names=elfrem.get_dynsym_names())

        elfrem.remove_symbols_from_dynsym()
        if elfrem.symtab is not None:
            elfrem.remove_symbols_from_symtab(overwrite=False)

        fd_tailored = open(TAILORED_FILE_PATH, 'rb')
        elf_after = ELFFile(fd_tailored)

        # Check symbol removal from .dynsym
        dynsym_before, symbols_before = self._get_defined_symbols(elf_before)
        dynsym_after, symbols_after = self._get_defined_symbols(elf_after)

        self.assertEqual(len(symbols_after), len(symbols_before) - 1)
        self.assertEqual(dynsym_after['sh_size'],
                         dynsym_before['sh_size'] - elf_before.structs.Elf_Sym.sizeof())

        # Check smaller hash section
        hash_before = elf_before.get_section_by_name('.gnu.hash')
        hash_after = elf_after.get_section_by_name('.gnu.hash')
        self.assertLess(hash_after['sh_size'], hash_before['sh_size'])

        # Check smaller dynstr section
        dynstr_before = elf_before.get_section_by_name('.dynstr')
        dynstr_after = elf_after.get_section_by_name('.dynstr')
        self.assertLess(dynstr_after['sh_size'], dynstr_before['sh_size'])

    def test_remove_reloc(self):
        fd = open(INPUT_FILE_PATH, 'rb')
        elf_before = ELFFile(fd)

        shutil.copyfile(INPUT_FILE_PATH, TAILORED_FILE_PATH)
        elfrem = ELFRemove(TAILORED_FILE_PATH)

        # divtest's address is taken in addrtaken, so removing divtest should
        # remove the relocation as well
        to_remove = ['divtest', 'addrtaken']
        elfrem.collect_symbols_in_dynsym(names=to_remove)
        if elfrem.symtab is not None:
            elfrem.collect_symbols_in_symtab(names=elfrem.get_dynsym_names())

        elfrem.remove_symbols_from_dynsym()
        if elfrem.symtab is not None:
            elfrem.remove_symbols_from_symtab(overwrite=False)

        fd_tailored = open(TAILORED_FILE_PATH, 'rb')
        elf_after = ELFFile(fd_tailored)

        # Check symbol removal from .dynsym
        dynsym_before, symbols_before = self._get_defined_symbols(elf_before)
        dynsym_after, symbols_after = self._get_defined_symbols(elf_after)

        self.assertEqual(len(symbols_after), len(symbols_before) - len(to_remove))
        self.assertEqual(dynsym_after['sh_size'],
                         dynsym_before['sh_size'] - len(to_remove) * elf_before.structs.Elf_Sym.sizeof())

        # Check smaller hash section
        hash_before = elf_before.get_section_by_name('.gnu.hash')
        hash_after = elf_after.get_section_by_name('.gnu.hash')
        self.assertLess(hash_after['sh_size'], hash_before['sh_size'])

        # Check smaller dynstr section
        dynstr_before = elf_before.get_section_by_name('.dynstr')
        dynstr_after = elf_after.get_section_by_name('.dynstr')
        self.assertLess(dynstr_after['sh_size'], dynstr_before['sh_size'])

        # Check smaller relocation section
        reloc_before = elf_before.get_section_by_name('.rela.dyn')
        reloc_after = elf_after.get_section_by_name('.rela.dyn')
        self.assertEqual(reloc_after['sh_size'],
                         reloc_before['sh_size'] - elf_before.structs.Elf_Rela.sizeof())

