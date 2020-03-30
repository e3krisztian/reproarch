#!/usr/bin/env python
# coding: utf-8

'''
Analyze Arch installation and display extra, missing and changed files.

This is done by comparing file system to the Arch installed packages database.

The Arch installed packages database is in the /var/lib/pacman/local/*/mtree
files, they contain a list of all the directories and files owned by the
packages as well as their properties: file modes and hashes!

Usage:
    sudo ./analyze_arch.py


Depending on available time this tool is intended to evolve into a install
reproduction tool that outputs some data file with which it is trivial
to reproduce the original system from scratch.

This "some data file" should include:
- list of installed packages
- modifications to the packages
- a script to install a new system and modify it as needed
'''

import argparse
import contextlib
from datetime import datetime
from glob import glob
import gzip
import hashlib
import re
import os
import tarfile
from typing import Tuple, Set

MEGABYTE = 1_000_000

KNOWN_NOT_PACKAGE_INSTALLED_AND_IGNORED_CHECKERS = [
    re.compile(x).search
    for x in (
        '^/home/',
        '^/tmp/', '^/dev/', '^/proc/', '^/sys/', '^/run/',
        # package ca-certificates-utils
        '^/etc/ca-certificates/extracted/',
        # package shared-mime-info
        '^/usr/share/mime/',
        # package ca-certificates-utils, openssl
        '^/etc/ssl/certs/',
        # ???
        '^/boot/EFI/BOOT/icons',
        # package pacman-mirrorlist ?
        '^/etc/pacman.d/gnupg/',
        # files that are created during use/not really worth backing up
        '^/var/cache/',
        '^/var/log/',
        '^/var/tmp/',
        '^/var/lib/docker',
        '^/var/lib/pacman/',
        '^/var/lib/systemd/coredump/',
        '/.cache/',
        # swap file[s]
        '^/swap',
    )]


def known_not_package_installed_and_ignored(path):
    return any(check(path) for check in KNOWN_NOT_PACKAGE_INSTALLED_AND_IGNORED_CHECKERS)


def main():
    if os.getuid() != 0:
        print('WARNING: Not running as root!')
        print(
            'WARNING: Expect differences to reality due to ' +
            'missing permissions to open files/look into directories.')

    new, missing, changed = analyze_system()

    def print_file_list(file_list_name, files):
        print()
        print(f'{file_list_name} {len(files)} files:')
        for file in sorted(files):
            print(f'- {file}')

    print_file_list('New (unknown)', new)
    print_file_list('Missing', missing)
    print_file_list('Changed', changed)

    print_sizes('Uncompressed new files archive size', new)
    archive(new, 'new.tar.gz')
    print_sizes('Uncompressed changed files archive size', changed)
    archive(changed, 'changed.tar.gz')


REPORTED_SIZE = 5_000_000

def print_sizes(msg, paths) -> int:
    print()
    print(f'Calculating file sizes (showing files that are more than {REPORTED_SIZE} big):')
    sum_sizes = 0
    for path in paths:
        try:
            size = os.path.getsize(path)
            if size > REPORTED_SIZE:
                print(f'- {path}: {size / MEGABYTE:0.2f}MB')
            sum_sizes += size
        except Exception as e:
            assert path in str(e)
            print(f'- ERROR: {e}')
    print(f'{msg}: {sum_sizes}')


def archive(files, output):
    if not files:
        print(f'no files to write to {output} - it is not created')
        return
    print(f'Creating archive {output}:')
    with tarfile.open(output, 'w:gz') as archive:
        for file in sorted(files):
            print(f'- {file}')
            archive.add(file, recursive=False)


def analyze_system(verbosity=1) -> Tuple[Set[str], Set[str], Set[str]]:
    @contextlib.contextmanager
    def progress(msg):
        if verbosity:
            start_time = datetime.now()
            print()
            print(f'STARTED {msg}')
            yield
            end_time = datetime.now()
            print(f'DONE   ({msg}) in {end_time - start_time}')
        else:
            yield

    with progress('reading install database (mtrees)'):
        mtree_keywords = read_all_mtrees()
        installed = set(mtree_keywords.keys())

    with progress('reading file system'):
        real_files = set(all_files())

        new = set(
            path
            for path in real_files.difference(installed)
            if not known_not_package_installed_and_ignored(path))

        missing = installed.difference(real_files)

    with progress('comparing file system against install database'):
        changed = set(
            path
            for path in real_files.intersection(installed)
            if not same_as_installed(path, mtree_keywords[path]))

    return new, missing, changed


###
# mtree file parsing
#
# `man mtree`:
#
#  Signature
#      The first line of any mtree file must begin with “#mtree”.  If a file
#      contains any full path entries, the first line should begin with
#      “#mtree v2.0”, otherwise, the first line should begin with
#      “#mtree v1.0”.
#  Blank
#      Blank lines are ignored.
#  Comment
#      Lines beginning with # are ignored.
#  Special
#      Lines beginning with / are special commands that influence the
#      interpretation of later lines.
#  Relative
#      If the first whitespace-delimited word has no / characters, it is the
#      name of a file in the current directory.  Any relative entry that
#      describes a directory changes the current directory.
#  dot-dot
#      As a special case, a relative entry with the filename .. changes the
#      current directory to the parent directory.  Options on dot-dot entries
#      are always ignored.
#  Full
#      If the first whitespace-delimited word has a / character after the
#      first character, it is the pathname of a file relative to the starting
#      directory.  There can be multiple full entries describing the same file.


def parse_keyword(word):
    key, _sep, value = word.partition(b'=')
    return key.strip(), value.strip()


OCTALS_REFS = re.compile(rb'\\([0-7][0-7][0-7])')


def octal_match_to_char(octal_match: bytes) -> bytes:
    return bytes([int(octal_match.group(1), base=8)])


def parse_path(word: bytes) -> str:
    return OCTALS_REFS.sub(octal_match_to_char, word).decode('utf-8')

assert parse_path(b'/path/to/strange\\033file') == '/path/to/strange\x1bfile'

# regression test for subtle bug, when converting first to utf-8, then resolving the octal references
assert parse_path(b'./usr/lib/go/test/fixedbugs/issue27836.dir/\\303\\204foo.go') == './usr/lib/go/test/fixedbugs/issue27836.dir/Äfoo.go'


open_mtree = gzip.open


def get_type(keywords):
    return keywords.get(b'type')


def parse_mtree(file_name, root='/'):
    '''
    Parse an mtree file and yield information about files contained.

    The yielded information is for each file/directory:
    - absolute file name
    - keywords for the file (including inherited ones)
    '''
    global_keywords = {}

    with open_mtree(file_name) as mtree_file:
        header = next(mtree_file).lstrip()
        assert header.startswith(b'#mtree'), header
        for line in mtree_file:
            line = line.lstrip()
            if not line:
                pass
            elif line.startswith(b'#'):
                # comment
                pass
            else:
                words = line.split()
                first_word = words[0]
                parsed_keywords = dict(parse_keyword(word) for word in words[1:])
                if first_word == b'/set':
                    global_keywords.update(parsed_keywords)
                elif first_word == b'/unset':
                    for key in parsed_keywords:
                        if key in global_keywords:
                            del global_keywords[key]
                else:
                    keywords = global_keywords.copy()
                    keywords.update(parsed_keywords)
                    path = parse_path(first_word)
                    abspath = os.path.normpath(os.path.join(root, path))
                    if get_type(keywords) == b'dir':
                        if '/' not in path:
                            root = abspath
                    yield abspath, keywords


###
# Arch install database
def read_all_mtrees():
    entries = {}
    for file_name in glob('/var/lib/pacman/local/*/mtree'):
        for path, keywords in parse_mtree(file_name):
            if path in entries:
                prev_type = get_type(entries[path])
                assert prev_type == get_type(keywords)
            entries[path] = keywords
    return entries


###
# All files on system
def all_files():
    for dirpath, dirnames, filenames in os.walk('/'):
        for name in filenames + dirnames:
            yield os.path.join(dirpath, name)


###
# Comparison
def type_eq(path, keywords):
    type = get_type(keywords)
    return (
        (type == b'file' and os.path.isfile(path)) or
        (type == b'dir'  and os.path.isdir(path)) or
        (type == b'link' and os.path.islink(path)))


def size_eq(path, keywords):
    assert os.path.isfile(path)
    return os.path.getsize(path) == int(keywords.get(b'size'))


def get_hash(path, hash_class):
    if not os.path.isfile(path):
        return 'not a file'
    hash = hash_class()
    with open(path, 'rb') as f:
        hash.update(f.read())
    return hash.hexdigest().lower()


def hash_eq(kwhash, path, hash_class):
    if not kwhash:
        return True
    realhash = get_hash(path, hash_class)
    return kwhash.decode('ascii').lower() == realhash


def same_as_installed(path, keywords):
    if not type_eq(path, keywords):
        return False
    if get_type(keywords) != b'file':
        return True
    try:
        return (
            size_eq(path, keywords) and
            hash_eq(keywords.get(b'md5digest'),    path, hashlib.md5) and
            hash_eq(keywords.get(b'sha256digest'), path, hashlib.sha256))
    except OSError:
        # not running as root?
        assert os.getuid() != 0
        return False


if __name__ == '__main__':
    main()
