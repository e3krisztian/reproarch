#!/usr/bin/env python
# coding: utf-8

'''
Analyze Arch installation and display/archive extra, missing and changed files.

This is done by comparing file system to the Arch installed packages database.

The Arch installed packages database is in the /var/lib/pacman/local/*/mtree
files, they contain a list of all the directories and files owned by the
packages as well as their properties: file modes and hashes.

Usage:
    sudo ./analyze_arch.py

Running as root is needed for proper operation, as some installed directories/files
have restrictions for security (e.g. /etc/sudoers, /etc/passwd)


DEVELOPMENT DIRECTION:

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
import subprocess
import tarfile
from typing import Tuple, Set

MEGABYTE = 1_000_000

IGNORED_PATH_CHECKERS = [
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


def is_ignored_path(path):
    return any(check(path) for check in IGNORED_PATH_CHECKERS)


# Parsed command line arguments/flags
args = None


def parse_args():
    parser = argparse.ArgumentParser()
    arg = parser.add_argument
    arg('--no-progress', action='store_false', dest='show_progress', default=True,
        help='Do not show progress when analyzing the system.')
    arg('--show-filenames', action='store_true', default=False,
        help='Show all new/changed/missing files in packages (this can be a huge output).')
    arg('-p', '--output-prefix', '--prefix', default='', dest='output_prefix',
        help='Raw string prefix for all generated files')
    arg('-n', '--dry-run', action='store_true', default=False,
        help='Do not write any output files')
    global args
    args = parser.parse_args()


def main():
    parse_args()

    if args.dry_run:
        print('Dry run - will not write any files, despite saying so.')
    if os.getuid() != 0:
        print('WARNING: Not running as root!')
        print(
            'WARNING: Expect differences to reality due to ' +
            'missing permissions to open files/look into directories.')

    save_package_info()

    new, missing, changed = compare_pacman_and_filesystem()

    print_file_list('New, non-package installed', new)
    print_file_list('Missing, package installed', missing)
    print_file_list('Changed, package installed', changed)

    print_sizes('Uncompressed new files archive size', new)
    archive(new, 'non-package-installed-files')
    print_sizes('Uncompressed changed files archive size', changed)
    archive(changed, 'changed-package-installed-files')


def save_package_info():
    def pacman(options, output_filename):
        command = f'/usr/bin/pacman {options}'
        full_output_filename = f'{args.output_prefix}{output_filename}'
        if args.show_progress:
            print(f'Creating "{full_output_filename}" from output of "{command}"')
        if args.dry_run:
            return
        with open(full_output_filename, 'w') as f:
            subprocess.run(command.split(), stdout=f)

    pacman('--query', 'all-packages.lst')
    # official packages (Arch main repos)
    pacman('--query --native --explicit', 'explicitly-installed-packages.lst')
    pacman('--query --native', 'native-packages.lst')
    # private packages (AUR)
    pacman('--query --foreign', 'private-packages.lst')
    pacman('--query --foreign --info', 'private-packages.info')
    pacman('--query --foreign --list', 'private-packages.files')


def print_file_list(file_list_name, files):
    if args.show_filenames:
        print()
        print(f'{file_list_name} {len(files)} files:')
        for file in sorted(files):
            print(f'- {file}')


REPORTED_SIZE = 5_000_000

def print_sizes(msg, paths) -> int:
    print()
    print(f'Calculating file sizes (showing files that are more than {REPORTED_SIZE} big):')
    sum_sizes = 0
    for path in paths:
        try:
            size = os.path.getsize(path)
            if size > REPORTED_SIZE and args.show_filenames:
                print(f'- {path}: {size / MEGABYTE:0.2f}MB')
            sum_sizes += size
        except Exception as e:
            assert path in str(e)
            print(f'- can not get size: {e}')
    print(f'{msg}: {sum_sizes}')


def archive(files, archive_name):
    archive_filename = f'{args.output_prefix}{archive_name}.tar'
    if not files:
        print(f'No files to write to "{archive_filename}" - it is not created')
        return
    print(f'Creating "{archive_filename}":')
    if args.dry_run:
        return
    # archive is to support deduplicating backup - like borg
    # and store permissions, links
    with tarfile.open(archive_filename, 'w') as archive:
        for file in sorted(files):
            if args.show_filenames:
                print(f'- {file}')
            archive.add(file, recursive=False)


def compare_pacman_and_filesystem() -> Tuple[Set[str], Set[str], Set[str]]:
    @contextlib.contextmanager
    def progress(msg):
        if args.show_progress:
            start_time = datetime.now()
            print()
            print(f'STARTED {msg}')
            yield
            end_time = datetime.now()
            print(f'DONE   ({msg}) in {end_time - start_time}')
        else:
            yield

    with progress('reading pacman install database (mtrees)'):
        mtree_keywords = read_all_mtrees()
        installed = set(mtree_keywords.keys())

    with progress('reading file system'):
        real_files = set(all_files())

        new = set(
            path
            for path in real_files.difference(installed)
            if not is_ignored_path(path))

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
assert parse_path(b'go/issue27836.dir/\\303\\204foo.go') == 'go/issue27836.dir/Äfoo.go'


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
