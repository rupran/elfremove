from setuptools import setup, find_packages

setup(
    name = 'ELFRemove',
    description = 'A library to remove functions from ELF files',
    author = 'Andreas Ziegler',
    author_email = 'andreas.ziegler@fau.de',
    url = 'https://github.com/rupran/elfremove',
    version = '0.1',
    license = 'GPL-3.0',
    packages = find_packages(),
    zip_safe = False,
    install_requires = [
        'pyelftools>=0.27',
        'pylibdebuginfod'
    ]
)
