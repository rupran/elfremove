# remove_from_elf
### Toolkit for the removal of symbols from ELF Files.
## GENERAL

The `remove_from_elf` toolkit allows the removal of symbols from executable
files using the ELF file format.
The removal can be achieved by manually stating the symbolnames or adresses
to be removed or based on the use-case usage analysis from
[`librarytrader`](https://gitlab.cs.fau.de/ziegler/librarytrader).

The toolset requiers `python3` and the `pyelftools` package. For tailoring using
the output of `librarytrader`, the librarytrader main directory has to be present in
the parent directory relative to the toolset.

By removing a Symbol, all references of it will be wiped from the file, including
Symbol-, Hash-, Relocation-Sections references. Furthermore the Code Segment of this
Symbol will be overwritten with '0xCC' Bytes.

## START-UP

The ELF File is examined for needed sections. If the ELF file is super stripped
a fallback to the DYNAMIC Segment is used.

## USAGE

The core is the `ELFRemove` class, which is used by utility scripts implemented in
this toolset.

### MANUAL REMOVAL

For manual removal `remove_tool.py` script is used.

**Usage:**

```
./remove_tool.py <ELF-File> <Sym1> ... <SymN>

	ELF-File: The File the given Symbols should be removed from.
	SymX:     The Symbolnames to be removed.
```

**Output:**

As a result the actual removed Symbols with detailed information are shown.

### USE-CASE REMOVAL

For removal of Symbols after a use-case analysis with librarytrader the `remove_tool_libtrader.py`
script can be used.
The script loads a Librarystore-Object created by librarytrader and tailors the including
files according to the analysis results.

**Output**:

As a result the removed Symbols or the statistics for each file is given.

## USAGE

```
./remove_tool_libtrader.py [-h] [-l] [--lib [LIB [LIB ...]]] [--libonly] [--overwrite] [-v] json

	json:  the json file from libtrader

optional arguments:
  -h, --help            show this help message and exit
  -l, --local           remove local functions
  --lib [LIB [LIB ...]]
                        list of librarys to be processed, use all librarys
                        from json file if not defined
  --libonly             name of binary has to start with 'lib'
  --overwrite           overwrite original library files, otherwise work with
                        a copy in the current working directory
  -v, --verbose         set verbosity
```
