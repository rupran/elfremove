# elfremove
### Toolkit for the removal of symbols from ELF files.
## GENERAL

The `elfremove` toolkit allows the removal of symbols from executable
files using the ELF file format.
The removal can be achieved by manually providing the symbol names or adresses
to be removed or based on the use-case specific analysis data generated from
[`librarytrader`](https://github.com/rupran/librarytrader).

The toolset requiers `python3` and the `pyelftools` package. For tailoring using
the output of `librarytrader`, the `librarytrader` module has to be installed on
the system or in the virtual environment. If it is not installed, the
`librarytrader` main directory can also be present in the parent directory,
next to this directory.

By removing a symbol, all references of it will be wiped from the file, including
references in the symbol table sections, hash sections,  and any references 
through relocation section entries. Furthermore, the code of this symbol will be
overwritten with '0xCC' bytes.

## START-UP

The ELF file is examined for required sections. If the ELF file is super stripped,
a fallback to the DYNAMIC Segment is used.

## USAGE

The core is the `ELFRemove` class, which is used by utility scripts implemented in
this toolset.

### MANUAL REMOVAL

For manual removal we provide the `remove_tool.py` script.

**Usage:**

```
./remove_tool.py <elf file> <Sym1> ... <SymN>

	elf file: The file the given symbols should be removed from.
	SymX:     The symbol names to be removed.
```

**Output:**

As a result the removed symbols are listed with detailed information.

### USE-CASE REMOVAL

For removal of symbols after a use-case analysis with librarytrader,
we additionally provide the `remove_tool_libtrader.py` script.
The script loads a `librarystore` object created and exported by `librarytrader`
and tailors the included files according to the analysis results.

**Usage:**

```
./remove_tool_libtrader.py [-h] [-l] [--lib [LIB [LIB ...]]] [--libonly] [--overwrite] [-v] json

	json:  the json file from librarytrader

optional arguments:
  -h, --help            show this help message and exit
  -l, --local           remove local functions
  --lib [LIB [LIB ...]]
                        list of librarys to be processed, use all librarys
                        from json file if not defined
  --libonly             name of binary has to start with 'lib'
  --overwrite           overwrite original library files, otherwise work with
                        a copy in the current working directory
  --addr_list           print list of removed locations (addresses) with size
  -v, --verbose         set verbosity
```

**Output**:

As a result, the removed symbols or the statistics for each file are printed and
the tailored files are written into a directory named `tailored_libs_<json>`
(except if the `--overwrite` flag is used where the files are directly
modified in the original location).
