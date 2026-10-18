#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Where ewsposter keeps its indexes, and which log file a counter of ews.idx belongs to """

import hashlib
import os
import shutil

INDEX_FILES = ('ews.idx', 'malware.md5')
SESSION_SUFFIX = '.session'
""" line 1 is hashed up to this many bytes """
FIRST_LINE_LIMIT = 64 * 1024


def indexFiles(folder):
    """ the index files in folder: ews.idx, malware.md5 and the *.session files of the session modules """
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return([])
    return([name for name in names
            if (name in INDEX_FILES or name.endswith(SESSION_SUFFIX)) and os.path.isfile(os.path.join(folder, name))])


def setupIndexDir(homedir, indexdir):
    """ create indexdir; when it is another folder than homedir and holds no index file yet, copy the
    index files of homedir into it. Returns the names copied. """
    os.makedirs(indexdir, exist_ok=True)

    if os.path.realpath(indexdir) == os.path.realpath(homedir) or indexFiles(indexdir):
        return([])

    copied = []
    for name in indexFiles(homedir):
        shutil.copy2(os.path.join(homedir, name), os.path.join(indexdir, name))
        copied.append(name)
    return(copied)


def fileIdentity(filename):
    """ '<inode>:<size>:<sha1 of line 1>' of a log file (the hash is empty while line 1 has no newline),
    None when the file does not exist """
    try:
        stat = os.stat(filename)
    except OSError:
        return(None)

    digest = ''
    try:
        with open(filename, 'rb') as logfile:
            first = logfile.readline(FIRST_LINE_LIMIT)
        if first.endswith(b'\n'):
            digest = hashlib.sha1(first).hexdigest()
    except OSError:
        pass

    return(f"{stat.st_ino}:{stat.st_size}:{digest}")


def sameFile(stored, current):
    """ False when current is another file than stored: another inode (rotated), smaller (truncated)
    or another line 1 (truncated and written again). A value that cannot be read counts as the same file. """
    try:
        inode, size, digest = stored.split(':', 2)
        current_inode, current_size, current_digest = current.split(':', 2)
        if inode != current_inode or int(current_size) < int(size):
            return(False)
    except ValueError:
        return(True)

    if digest and current_digest and digest != current_digest:
        return(False)
    return(True)
