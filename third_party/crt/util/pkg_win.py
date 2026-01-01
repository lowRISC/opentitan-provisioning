#!/usr/bin/env python3
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

#############################################################################
# Create a Windows ZIP archive with needed binary resources.
#
#############################################################################
import argparse
import errno
import logging
import os
import os.path
import struct
import subprocess
import sys
import zipfile

flags = argparse.ArgumentParser(description='Windows Packaging Tool')
flags.add_argument('files', metavar='FILE', type=str, nargs='*', help='Files')
flags.add_argument('--ignore_missing_dlls',
                   default=False,
                   type=bool,
                   help='Ignore missing DLLs')
flags.add_argument('--objdump_bin', default=None, help='objdump binary')
flags.add_argument('--out', default=None, help='Output ZIP file.')
flags.add_argument('--mxe', default=None, help='Location of MXE install.')
flags.add_argument('--skip_dlls',
                   default=None,
                   help='DLL dependencies to ignore.')
flags.add_argument('--combine_zips',
                   default=None,
                   help='Combine extra ZIP archives into this one.')
flags.add_argument('--target',
                   default='win64',
                   help='Target platform (win32 or win64).')
flags.add_argument('--debuglog',
                   default=None,
                   help='File to write debug log into')

# Target name mappings to mxe directory names.
TARGET = {
    'win32': 'i686-w64-mingw32.shared',
    'win64': 'x86_64-w64-mingw32.shared',
}

# ELF target name mappings to mxe directory names.
PREFIX = {
    'pei-i386': 'i686-w64-mingw32.shared',
    'pei-x86-64': 'x86_64-w64-mingw32.shared',
}

# PE-COFF identifiers per architecture.
ARCH_TO_TARGET = {
    0x8664: 'win64',
    0x014c: 'win32',
}

# DLLs that are part of Windows.  If a program has a dependency on one of
# of these DLLs, we assume Windows will provide the DLL.
SKIP_DLLS = [
    'api-ms-win-crt-conio-l1-1-0.dll',
    'api-ms-win-crt-convert-l1-1-0.dll',
    'api-ms-win-crt-environment-l1-1-0.dll',
    'api-ms-win-crt-filesystem-l1-1-0.dll',
    'api-ms-win-crt-heap-l1-1-0.dll',
    'api-ms-win-crt-locale-l1-1-0.dll',
    'api-ms-win-crt-math-l1-1-0.dll',
    'api-ms-win-crt-process-l1-1-0.dll',
    'api-ms-win-crt-runtime-l1-1-0.dll',
    'api-ms-win-crt-stdio-l1-1-0.dll',
    'api-ms-win-crt-string-l1-1-0.dll',
    'api-ms-win-crt-time-l1-1-0.dll',
    'api-ms-win-crt-utility-l1-1-0.dll',
    'ADVAPI32.DLL',
    'BCRYPT.DLL',
    'CABINET.DLL',
    'CRYPT32.DLL',
    'DBGHELP.DLL',
    'GDI32.DLL',
    'IMM32.DLL',
    'KERNEL32.DLL',
    'MSI.DLL',
    'MSVCRT.DLL',
    'OLE32.DLL',
    'OLEAUT32.DLL',
    'OPENGL32.DLL',
    'RPCRT4.DLL',
    'SETUPAPI.DLL',
    'SHELL32.DLL',
    'SHLWAPI.DLL',
    'USER32.DLL',
    'VCRUNTIME140.DLL',
    'VERSION.DLL',
    'WINMM.DLL',
    'WS2_32.DLL',
]

# The following DLLs are part of how exception handling is implemented.
REQUIRED_DLLS = {
    'pei-i386': [
        'libgcc_s_sjlj-1.dll',
    ],
    'pei-x86-64': [
        'libgcc_s_seh-1.dll',
    ],
}


class PkgWin(object):

    def __init__(self, args):
        self.missing_dlls = 0
        self.mxe = args.mxe
        self.target = args.target
        self.objdump_bin = args.objdump_bin if args.objdump_bin else os.path.join(
            self.mxe, 'bin', TARGET[self.target] + '-objdump')

    def detect_exe(self, filename):
        """Detect whether `filename` is a PE-COFF executable.

        Args:
          filename: str; Path to a file.
        Returns:
          If an executabe: str "win32" or "win64".
          If not an executable: None
        """
        with open(filename, 'rb') as f:
            hdr = f.read(4096)
            if (hdr[:2] == b'MZ'
                    and b'This program cannot be run in DOS mode' in hdr):
                logging.info('Detected legacy DOS header in %r', filename)
                (pehdr, ) = struct.unpack('<L', hdr[0x3c:0x40])
                (signature, arch) = struct.unpack('<LH', hdr[pehdr:pehdr + 6])
                logging.info('Found PE header at %#x: sig=%08x arch=%04x',
                             pehdr, signature, arch)
                return ARCH_TO_TARGET.get(arch, 'unknown')
        return None

    def detect_dlls(self, args, filename, dlls):
        """Detect which DLLs are required by the executable `filename`.

        Args:
          args: ArgParse arguments.
          filename: str; Path to a file.
          dlls: set; A set of DLLs.
        """
        peformat = None
        logging.info('Inspecting %r', filename)
        cmd = [self.objdump_bin, '-p', filename]
        data = subprocess.check_output(cmd, universal_newlines=True)
        for line in data.splitlines():
            if 'file format ' in line:
                peformat = line.split()[-1]
            elif 'DLL Name: ' in line:
                dll = line.split()[-1]
                if dll.upper() in SKIP_DLLS:
                    continue
                dllpath = os.path.join(self.mxe, PREFIX[peformat], 'bin', dll)
                if dllpath in dlls:
                    continue

                if os.path.isfile(dllpath):
                    dlls.add(dllpath)
                    self.detect_dlls(args, dllpath, dlls)
                else:
                    logging.warning(
                        'The file %r does not exist.  Add it to '
                        'skip_dlls if it is a standard windows DLL.', dll)
                    self.missing_dlls += 1

        for dll in REQUIRED_DLLS[peformat]:
            dll = os.path.join(self.mxe, PREFIX[peformat], 'bin', dll)
            dlls.add(dll)

    def package(self, args):
        """Package executables and required DLLs into a ZIP archive."""
        dlls = set()
        for f in args.files:
            arch = self.detect_exe(f)
            if arch:
                if arch != self.target:
                    logging.warning(
                        'Unexpected target for %r: %s (expected %s)', f,
                        arch, self.target)
                self.detect_dlls(args, f, dlls)

        if self.missing_dlls and not args.ignore_missing_dlls:
            return 1

        with zipfile.ZipFile(args.out, 'w', zipfile.ZIP_DEFLATED) as z:
            for f in args.files:
                z.write(f, os.path.basename(f))

            for d in sorted(dlls):
                z.write(d, os.path.basename(d))

            if args.combine_zips:
                for archive in args.combine_zips.split(','):
                    with zipfile.ZipFile(archive, 'r') as ar:
                        for f in ar.namelist():
                            z.writestr(f, ar.read(f))
        return 0


def main(argv):
    global SKIP_DLLS
    args = flags.parse_args(argv[1:])
    if args.debuglog:
        logging.basicConfig(level=logging.INFO, filename=args.debuglog)
    if not args.out:
        logging.error('No output file specified (use --out)')
        return 1

    if args.skip_dlls:
        SKIP_DLLS += args.skip_dlls.split(',')
    SKIP_DLLS = list(map(str.upper, SKIP_DLLS))

    pw = PkgWin(args)
    return pw.package(args)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
