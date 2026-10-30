# -*- coding: utf-8 -*-
"""Inject the 89 dual-chain loader into an already built unsigned IPA.

Usage: python3 scripts/inject_89.py <input.ipa> <output.ipa>
Reads bundled components from native/Frameworks and inserts:
  * Frameworks/libwebuiopsercore.framework
  * Frameworks/SDWebuiopser.framework
  * Frameworks/libuiopsersvc.framework
  * Frameworks/libxpf.dylib
  * Frameworks/libgrabkernel2.dylib
  * loader89.dylib at the app root
  * LC_LOAD_DYLIB @executable_path/loader89.dylib
"""
import hashlib
import plistlib
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / 'native/Frameworks/loader89_arm64.dylib'
LOAD_PATH = '@executable_path/Frameworks/loader89.dylib'
COPY_ITEMS = [
    'Frameworks/libwebuiopsercore.framework',
    'Frameworks/SDWebuiopser.framework',
    'Frameworks/libuiopsersvc.framework',
    'Frameworks/libxpf.dylib',
    'Frameworks/libgrabkernel2.dylib',
]
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018


def read_cstr(data, off):
    end = data.find(b'\0', off)
    return data[off:end].decode('utf-8', 'replace')


def parse_macho(data):
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == 0xFEEDFACF:
        return [(0, len(data))]
    if magic == 0xBEBAFECA:
        nfat = struct.unpack_from('>I', data, 4)[0]
        out = []
        for i in range(nfat):
            _, _, off, size, _align = struct.unpack_from('>5I', data, 8 + i * 20)
            if struct.unpack_from('<I', data, off)[0] == 0xFEEDFACF:
                out.append((off, size))
        return out
    raise RuntimeError('not a Mach-O or FAT binary')


def insert_load_command(data, base, limit, load_path):
    magic, _, _, _, ncmds, sizeofcmds, _ = struct.unpack_from('<7I', data, base)
    if magic != 0xFEEDFACF:
        raise RuntimeError('not a 64-bit Mach-O slice')
    end = base + 32 + sizeofcmds
    min_off = limit
    off = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmdsize == 0:
            break
        if cmd == LC_SEGMENT_64:
            _, _, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            if fileoff > 0:
                min_off = min(min_off, fileoff)
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            p = off + 72
            for _ in range(nsects):
                _, _, sectoff = struct.unpack_from('<QQI', data, p + 32)
                if sectoff > 0:
                    min_off = min(min_off, sectoff)
                p += 80
        else:
            if cmd in (2, 11, 29, 38, 41, 42, 0x80000034, 34, 0x80000022, 27, 28):
                fileoff, _ = struct.unpack_from('<II', data, off + 8)
                if fileoff > 0:
                    min_off = min(min_off, fileoff)
        off += cmdsize
    name = load_path.encode() + b'\0'
    padded = (len(name) + 7) & ~7
    need = 24 + padded
    gap = min_off - end
    if gap < need:
        raise RuntimeError(f'header padding too small: need {need}, have {gap}')
    probe = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, probe)
        if cmdsize == 0:
            break
        if cmd in (LC_LOAD_DYLIB, 0x80000018):
            nameoff = struct.unpack_from('<I', data, probe + 8)[0]
            if read_cstr(bytes(data), probe + nameoff) == load_path:
                print(f'  load command already present @0x{probe:x}')
                return
        probe += cmdsize
    newlc = struct.pack('<IIIIII', LC_LOAD_WEAK_DYLIB, need, 24, 0, 0, 0) + name + b'\0' * (padded - len(name))
    data[end:end + need] = newlc
    struct.pack_into('<I', data, base + 16, ncmds + 1)
    struct.pack_into('<I', data, base + 20, sizeofcmds + need)
    print(f'  inserted load command @0x{end:x} ({ncmds}->{ncmds + 1}, +{need}B)')


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: inject_89.py <input.ipa> [output.ipa]')
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2]) if len(sys.argv) == 3 else src.with_name(src.stem + '-89inject.ipa')
    print(f'injection input: {src}')
    print(f'injection output: {dst}')
    with zipfile.ZipFile(src) as z:
        order = [(i.filename, i.date_time) for i in z.infolist() if not i.filename.endswith('/')]
        entries = {name: z.read(name) for name, _ in order}
    apps = sorted({n.split('/')[1] for n in entries if n.startswith('Payload/') and n.count('/') >= 2})
    if not apps:
        raise RuntimeError('Payload app not found')
    app = apps[0]
    appdir = f'Payload/{app}/'
    print(f'app: {app}')
    info = plistlib.loads(entries[appdir + 'Info.plist'])
    exe = info['CFBundleExecutable']
    main_key = appdir + exe
    main = bytearray(entries[main_key])
    print(f'main binary: {exe} ({len(main):,} bytes)')
    for base, size in parse_macho(bytes(main)):
        insert_load_command(main, base, min(size, len(main) - base), LOAD_PATH)
    entries[main_key] = bytes(main)
    for item in COPY_ITEMS:
        source = ROOT / 'native' / item
        if source.is_dir():
            for path in source.rglob('*'):
                if path.is_file():
                    rel = path.relative_to(ROOT / 'native')
                    entries[appdir + str(rel).replace('\\', '/')] = path.read_bytes()
            print(f'copied directory: {item}')
        elif source.is_file():
            entries[appdir + item] = source.read_bytes()
            print(f'copied file: {item} ({source.stat().st_size:,} bytes)')
        else:
            raise RuntimeError(f'missing bundled item: {source}')
    entries[appdir + 'Frameworks/loader89.dylib'] = LOADER.read_bytes()
    print(f'loader: loader89.dylib ({LOADER.stat().st_size:,} bytes)')
    cr_key = appdir + '_CodeSignature/CodeResources'
    if cr_key in entries:
        raw = entries[cr_key]
        fmt = plistlib.FMT_XML if raw.lstrip().startswith(b'<?xml') else plistlib.FMT_BINARY
        cr = plistlib.loads(raw)
        data = entries[appdir + 'Frameworks/loader89.dylib']
        item = dict(cr['files2'].get('Frameworks/loader89.dylib') or {})
        item['hash'] = hashlib.sha1(data).digest()
        item['hash2'] = hashlib.sha256(data).digest()
        cr['files2']['Frameworks/loader89.dylib'] = item
        if 'files' in cr:
            cr['files']['Frameworks/loader89.dylib'] = item['hash']
        entries[cr_key] = plistlib.dumps(cr, fmt=fmt)
        print('CodeResources: loader89.dylib hash updated')
    with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zo:
        for name, _time in order:
            if name in entries:
                zo.writestr(name, entries[name])
        existing = {name for name, _ in order}
        for name, data in entries.items():
            if name not in existing:
                zo.writestr(name, data)
    print(f'output size: {dst.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
