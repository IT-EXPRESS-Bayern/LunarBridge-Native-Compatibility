# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 IT-EXPRESS Bayern and LunarBridge contributors.
"""Read-only macOS software prerequisites; API reports are not GPU execution proof."""
import argparse
import ctypes as c
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import struct
import subprocess
import sys
import tempfile

MAX_APPS = 16
MAX_COMMAND_BYTES = 128 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_LOAD_COMMAND_BYTES = 8 * 1024 * 1024
MAX_ARCHITECTURES = 16
FRAMEWORKS = ('AppKit', 'Metal', 'CoreImage', 'VideoToolbox', 'AVFoundation', 'CoreML')
LIBRARY_MARKERS = {f'/System/Library/Frameworks/{name}.framework/': name
                   for name in (*FRAMEWORKS, 'AGL')}
THIN_MAGIC = {b'\xcf\xfa\xed\xfe': ('<', True), b'\xfe\xed\xfa\xcf': ('>', True),
              b'\xce\xfa\xed\xfe': ('<', False), b'\xfe\xed\xfa\xce': ('>', False)}
FAT_MAGIC = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
             b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
DYLIB_COMMANDS = {0xC, 0x80000018, 0x8000001F, 0x80000023}
SOURCES = {
    'metal': 'https://support.apple.com/en-us/102894',
    'rosetta': 'https://support.apple.com/en-us/102527',
    'tahoe': 'https://developer.apple.com/documentation/macos-release-notes/macos-26-release-notes',
    'macho': 'https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h',
    'decode': 'https://developer.apple.com/documentation/videotoolbox/vtishardwaredecodesupported(_:)',
    'kext_policy': 'https://support.apple.com/guide/deployment/system-extensions-in-macos-depa5fb8376f/web',
}


class InputError(ValueError):
    """Fixed codes only: never copy paths, metadata or native stderr to reports."""


def parse_version(value):
    if not isinstance(value, str) or len(value) > 24 or not re.fullmatch(r'\d{1,5}(?:\.\d{1,5}){0,2}', value):
        raise InputError('invalid_version')
    parts = tuple(int(item) for item in value.split('.'))
    return parts + (0,) * (3 - len(parts))


def version_text(value):
    return '.'.join(str(part) for part in value)


def packed_version(value):
    return value >> 16, (value >> 8) & 255, value & 255


def architecture(cpu, subtype):
    if cpu == 0x01000007:
        return {3: 'x86_64', 8: 'x86_64h'}.get(subtype & 0xFFFFFF, 'x86_64_other')
    if cpu == 0x0100000C:
        return 'arm64e' if subtype & 0xFFFFFF == 2 else 'arm64'
    return {7: 'i386', 12: 'arm', 18: 'ppc', 0x01000012: 'ppc64'}.get(cpu, 'other')


def open_regular(path):
    """Reject special files before opening and recheck without FIFO blocking."""
    target = Path(path)
    before = target.stat()
    if not stat.S_ISREG(before.st_mode):
        raise InputError('not_regular_file')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(target, flags)
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise InputError('not_regular_file')
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise InputError('input_changed_before_open')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def inspect_binary(path):
    """Inspect bounded header regions of an explicitly selected Mach-O executable."""
    with open_regular(path) as handle:
        properties = os.fstat(handle.fileno())
        if not stat.S_ISREG(properties.st_mode):
            raise InputError('not_regular_file')
        file_bytes = properties.st_size

        def region(offset, length):
            if offset < 0 or length < 0 or length > MAX_LOAD_COMMAND_BYTES or \
                    offset > file_bytes or length > file_bytes - offset:
                raise InputError('binary_range_invalid')
            handle.seek(offset)
            result = handle.read(length)
            if len(result) != length:
                raise InputError('binary_changed_or_truncated')
            return result

        magic = region(0, 4)
        if magic in FAT_MAGIC:
            endian, wide = FAT_MAGIC[magic]
            count = struct.unpack(endian + 'I', region(4, 4))[0]
            if not 1 <= count <= MAX_ARCHITECTURES:
                raise InputError('architecture_count_invalid')
            entry_bytes = 32 if wide else 20
            table_end = 8 + count * entry_bytes
            table = region(8, count * entry_bytes)
            slices = []
            for index in range(count):
                values = struct.unpack_from(endian + ('IIQQII' if wide else 'IIIII'), table,
                                            index * entry_bytes)
                cpu, subtype, offset, length, alignment = values[:5]
                if (wide and values[5]) or alignment > 31 or offset < table_end or \
                        offset % (1 << alignment) or length < 28 or offset > file_bytes or length > file_bytes - offset:
                    raise InputError('fat_slice_invalid')
                if any(offset < previous[0] + previous[1] and previous[0] < offset + length for previous in slices):
                    raise InputError('fat_slices_overlap')
                slices.append((offset, length, cpu, subtype))
        elif magic in THIN_MAGIC:
            slices = [(0, file_bytes, None, None)]
        else:
            raise InputError('not_macho')

        result = []
        seen = set()
        for offset, slice_bytes, outer_cpu, outer_subtype in slices:
            item_magic = region(offset, 4)
            if item_magic not in THIN_MAGIC:
                raise InputError('slice_not_macho')
            endian, wide = THIN_MAGIC[item_magic]
            header_bytes = 32 if wide else 28
            if slice_bytes < header_bytes:
                raise InputError('macho_header_truncated')
            fields = struct.unpack(endian + ('8I' if wide else '7I'), region(offset, header_bytes))
            cpu, subtype, kind, count, command_bytes = fields[1:6]
            if bool(cpu & 0x01000000) != wide:
                raise InputError('macho_cpu_width_mismatch')
            if kind != 2:
                raise InputError('not_executable')
            if (wide and fields[7]) or count > 4096 or command_bytes > MAX_LOAD_COMMAND_BYTES or \
                    command_bytes > slice_bytes - header_bytes:
                raise InputError('load_command_bounds_invalid')
            if outer_cpu is not None and (cpu != outer_cpu or subtype != outer_subtype):
                raise InputError('fat_cpu_mismatch')
            if (cpu, subtype) in seen:
                raise InputError('duplicate_architecture')
            seen.add((cpu, subtype))
            commands = region(offset + header_bytes, command_bytes)
            position = 0
            minimums, platforms, linked = [], set(), set()
            for _ in range(count):
                if position + 8 > len(commands):
                    raise InputError('load_command_truncated')
                command, length = struct.unpack_from(endian + 'II', commands, position)
                if length < 8 or length % (8 if wide else 4) or length > len(commands) - position:
                    raise InputError('load_command_invalid')
                block = commands[position:position + length]
                if command == 0x32:
                    if length < 24:
                        raise InputError('build_version_invalid')
                    target_platform, minos, sdk, tool_count = struct.unpack_from(endian + '4I', block, 8)
                    if length != 24 + tool_count * 8:
                        raise InputError('build_tool_count_invalid')
                    platforms.add(target_platform)
                    if target_platform in (1, 6):
                        minimums.append(packed_version(minos))
                elif command in (0x24, 0x25, 0x2F, 0x30):
                    if length != 16:
                        raise InputError('minimum_os_command_invalid')
                    platforms.add({0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}[command])
                    if command == 0x24:
                        minimums.append(packed_version(struct.unpack_from(endian + 'I', block, 8)[0]))
                elif command in DYLIB_COMMANDS:
                    if length < 24:
                        raise InputError('dylib_command_invalid')
                    name_offset = struct.unpack_from(endian + 'I', block, 8)[0]
                    if name_offset < 24 or name_offset >= length:
                        raise InputError('dylib_name_invalid')
                    terminator = block.find(b'\0', name_offset)
                    if terminator < 0 or terminator - name_offset > 4096:
                        raise InputError('dylib_name_invalid')
                    name = block[name_offset:terminator].decode('utf-8', 'replace')
                    linked.update(label for marker, label in LIBRARY_MARKERS.items() if name.startswith(marker))
                position += length
            if position != len(commands):
                raise InputError('load_command_size_mismatch')
            result.append({'architecture': architecture(cpu, subtype),
                           'minimum_macos': version_text(max(minimums)) if minimums else None,
                           'platforms': sorted(platforms), 'linked_frameworks': sorted(linked)})
        return result


def app_report(path, index, host_version=None):
    """Never execute an app, enumerate other apps or expose its name/path/identifier."""
    report = {'selection_index': index, 'state': 'unverified', 'launch_tested': False,
              'plugins_and_transitive_dependencies_checked': False, 'codes': []}
    try:
        root = Path(path).resolve(strict=True)
        minimums = []
        if root.is_dir():
            if root.suffix.lower() != '.app':
                raise InputError('expected_app_bundle')
            metadata = (root / 'Contents/Info.plist').resolve(strict=True)
            if not metadata.is_relative_to(root) or not metadata.is_file() or metadata.stat().st_size > MAX_METADATA_BYTES:
                raise InputError('app_metadata_bounds_invalid')
            with open_regular(metadata) as handle:
                raw = handle.read(MAX_METADATA_BYTES + 1)
            if len(raw) > MAX_METADATA_BYTES:
                raise InputError('app_metadata_bounds_invalid')
            values = plistlib.loads(raw)
            if not isinstance(values, dict):
                raise InputError('app_metadata_invalid')
            name = values.get('CFBundleExecutable')
            if not isinstance(name, str) or not name or len(name) > 255 or name in ('.', '..') or \
                    any(character in name for character in ('/', '\\', '\0')):
                raise InputError('app_executable_invalid')
            executable = (root / 'Contents/MacOS' / name).resolve(strict=True)
            if not executable.is_relative_to(root):
                raise InputError('app_executable_outside_bundle')
            if 'LSMinimumSystemVersion' in values:
                minimums.append(parse_version(values['LSMinimumSystemVersion']))
            by_arch = values.get('LSMinimumSystemVersionByArchitecture', {})
            if not isinstance(by_arch, dict):
                raise InputError('app_minimum_arch_invalid')
            if 'x86_64' in by_arch:
                minimums.append(parse_version(by_arch['x86_64']))
        else:
            executable = root
        slices = inspect_binary(executable)
        report['slices'] = slices
        candidates = [item for item in slices if item['architecture'] == 'x86_64']
        if not candidates:
            if any(item['architecture'] == 'x86_64h' for item in slices):
                report['codes'].append('CPU_SUBTYPE_REQUIREMENTS_UNVERIFIED')
            else:
                report['state'] = 'blocked'
                report['codes'].append('NO_X86_64_EXECUTABLE')
            return report
        candidate = candidates[0]
        if candidate['platforms'] and not all(item in (1, 6) for item in candidate['platforms']):
            report['state'] = 'blocked'
            report['codes'].append('NON_MACOS_EXECUTABLE')
            return report
        if candidate['minimum_macos']:
            minimums.append(parse_version(candidate['minimum_macos']))
        report['required_macos'] = version_text(max(minimums)) if minimums else None
        if host_version and minimums and max(minimums) > parse_version(host_version):
            report['state'] = 'blocked'
            report['codes'].append('MACOS_VERSION_TOO_OLD')
            return report
        if 'AGL' in candidate['linked_frameworks']:
            report['codes'].append('TAHOE_AGL_FUNCTIONS_HAVE_NO_EFFECT')
        if not host_version or not minimums or not candidate['platforms']:
            report['codes'].append('OS_REQUIREMENTS_INCOMPLETE')
        report['state'] = 'metadata_prerequisites_satisfied' if host_version and minimums and candidate['platforms'] else 'unverified'
        report['codes'].append('RUNTIME_AND_DEPENDENCIES_UNVERIFIED')
    except InputError as exc:
        report['codes'].append(str(exc))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, struct.error, plistlib.InvalidFileException):
        report['codes'].append('APP_INPUT_UNREADABLE_OR_INVALID')
    return report


def command(arguments):
    # Fixed read-only OS commands only. Native stderr is discarded, including paths.
    try:
        proc = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=15, check=False)
        if len(proc.stdout) > MAX_COMMAND_BYTES:
            return {'state': 'output_limit', 'returncode': None, 'data': b''}
        return {'state': 'observed' if proc.returncode == 0 else 'command_failed',
                'returncode': proc.returncode, 'data': proc.stdout}
    except subprocess.TimeoutExpired:
        return {'state': 'timeout', 'returncode': None, 'data': b''}
    except OSError:
        return {'state': 'unavailable', 'returncode': None, 'data': b''}


def policy_report(kind, result):
    text = result['data'].decode('utf-8', 'replace').strip().lower()
    value = 'unknown'
    if result['state'] == 'observed':
        if kind == 'sip':
            if re.fullmatch(r'system integrity protection status: enabled\.', text):
                value = 'enabled'
            elif re.fullmatch(r'system integrity protection status: disabled\.', text):
                value = 'disabled'
            elif 'custom configuration' in text:
                value = 'custom_configuration'
        elif text in ('assessments enabled', 'assessments disabled'):
            value = text.split()[1]
    return {'query_state': result['state'], 'state': value,
            'individual_kext_loading_verified': False}


def metal_report():
    """Query public device enumeration only, without creating/submitting GPU commands."""
    objc = c.CDLL('/usr/lib/libobjc.A.dylib')
    objc.objc_getClass.argtypes, objc.objc_getClass.restype = [c.c_char_p], c.c_void_p
    objc.sel_registerName.argtypes, objc.sel_registerName.restype = [c.c_char_p], c.c_void_p
    send_pointer = c.CFUNCTYPE(c.c_void_p, c.c_void_p, c.c_void_p)(('objc_msgSend', objc))
    send_count = c.CFUNCTYPE(c.c_ulong, c.c_void_p, c.c_void_p)(('objc_msgSend', objc))
    send_void = c.CFUNCTYPE(None, c.c_void_p, c.c_void_p)(('objc_msgSend', objc))
    select = objc.sel_registerName
    foundation = c.CDLL('/System/Library/Frameworks/Foundation.framework/Foundation')
    pool_class = objc.objc_getClass(b'NSAutoreleasePool')
    if not pool_class:
        raise InputError('metal_runtime_unavailable')
    pool = send_pointer(send_pointer(pool_class, select(b'alloc')), select(b'init'))
    if not pool:
        raise InputError('metal_runtime_unavailable')
    devices = None
    try:
        metal = c.CDLL('/System/Library/Frameworks/Metal.framework/Metal')
        metal.MTLCopyAllDevices.argtypes, metal.MTLCopyAllDevices.restype = [], c.c_void_p
        devices = metal.MTLCopyAllDevices()
        if not devices:
            count = 0
        else:
            count = send_count(devices, select(b'count'))
        if count > 32:
            raise InputError('metal_device_count_invalid')
        return {'state': 'api_reported' if count else 'no_device_reported', 'device_count': count,
                'gpu_execution_verified': False, 'target_arc130v_binding_verified': False,
                'metal4_on_intel_supported_by_apple': False}
    finally:
        if devices:
            send_void(devices, select(b'release'))
        if pool:
            send_void(pool, select(b'drain'))


def decode_report():
    toolbox = c.CDLL('/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox')
    probe = toolbox.VTIsHardwareDecodeSupported
    probe.argtypes, probe.restype = [c.c_uint32], c.c_bool
    return {'state': 'api_reported', 'hardware_decode_reported': {
        name: bool(probe(int.from_bytes(code, 'big'))) for name, code in
        (('h264', b'avc1'), ('hevc', b'hvc1'), ('av1', b'av01'))},
        'decode_execution_verified': False, 'encode_execution_verified': False}


def collect(apps=()):
    if len(apps) > MAX_APPS:
        raise InputError('too_many_apps')
    report = {'schema': 1, 'state': 'unsupported-platform', 'target_architecture': 'x86_64',
              'platform': 'macos' if sys.platform == 'darwin' else 'other',
              'runtime': {'state': 'not_checked'}, 'native_target_boot_verified': False,
              'target_hardware_identity_verified': False, 'app_inventory_scanned': False,
              'gpu_execution_verified': False, 'media_execution_verified': False,
              'firmware_secure_boot': {'state': 'unverified', 'required_enabled': True,
                                       'apple_secure_boot_model_is_firmware_secure_boot': False},
              'apps': [{'selection_index': index, 'state': 'not_checked',
                        'launch_tested': False, 'codes': ['MACOS_RUNTIME_REQUIRED']}
                       for index in range(1, len(apps) + 1)],
              'findings': [], 'sources': SOURCES.copy()}
    if sys.platform != 'darwin':
        report['findings'].append({'code': 'MACOS_RUNTIME_REQUIRED', 'state': 'blocked'})
        return report
    machine = platform.machine().lower()
    machine = machine if machine in ('x86_64', 'arm64') else 'other'
    report['state'] = 'macos-runtime-observed'
    report['runtime'] = {'state': 'observed', 'architecture': machine, 'macos_version': None}
    result = command(['/usr/bin/sw_vers', '-productVersion'])
    if result['state'] == 'observed':
        try:
            report['runtime']['macos_version'] = version_text(parse_version(result['data'].decode('ascii').strip()))
        except (ValueError, UnicodeError):
            pass
    version = report['runtime']['macos_version']
    if not version or parse_version(version)[0] != 26:
        report['findings'].append({'code': 'TARGET_TAHOE_VERSION_UNCONFIRMED', 'state': 'unverified'})
    if machine != 'x86_64':
        report['findings'].append({'code': 'TARGET_INTEL_RUNTIME_UNCONFIRMED', 'state': 'unverified'})
    report['frameworks'] = {name: {'state': 'bundle_present' if
        (Path('/System/Library/Frameworks') / (name + '.framework')).is_dir() else 'bundle_absent',
        'functional_runtime_verified': False} for name in FRAMEWORKS}
    for name, probe in (('metal', metal_report), ('video_decode', decode_report)):
        try:
            report[name] = probe()
        except (OSError, AttributeError, InputError, ValueError):
            report[name] = {'state': 'query_unavailable', 'execution_verified': False}
    windows = command(['/usr/bin/pgrep', '-x', 'WindowServer'])
    report['windowserver'] = {'state': 'process_observed' if windows['state'] == 'observed' else
        'process_not_observed' if windows['returncode'] == 1 else 'query_unavailable',
        'accelerated_compositing_verified': False}
    report['sip'] = policy_report('sip', command(['/usr/bin/csrutil', 'status']))
    report['gatekeeper'] = policy_report('gatekeeper', command(['/usr/sbin/spctl', '--status']))
    report['apps'] = [app_report(path, index, version) for index, path in enumerate(apps, 1)]
    if report['metal']['state'] == 'no_device_reported':
        report['findings'].append({'code': 'METAL_DEVICE_NOT_REPORTED', 'state': 'missing'})
    report['findings'].extend([
        {'code': 'GPU_EXECUTION_UNTESTED', 'state': 'unverified'},
        {'code': 'VIDEO_EXECUTION_UNTESTED', 'state': 'unverified'},
        {'code': 'FIRMWARE_SECURE_BOOT_UNVERIFIED', 'state': 'unverified'},
        {'code': 'TARGET_HARDWARE_IDENTITY_UNVERIFIED', 'state': 'unverified'}])
    return report


def report_destination(path, apps):
    """The sole write target must be a JSON report outside apps, EFI and OS trees."""
    candidate = Path(path)
    resolved = candidate.resolve()
    if candidate.is_symlink() or resolved.suffix.lower() != '.json':
        raise InputError('invalid_report_destination')
    for part in resolved.parts:
        if part.upper() == 'EFI' or part.lower().endswith(('.app', '.kext', '.framework', '.systemextension')):
            raise InputError('report_destination_is_protected')
    if sys.platform == 'darwin' and any(resolved.is_relative_to(Path(root).resolve()) for root in
        ('/System', '/Library', '/usr', '/bin', '/sbin', '/private/var')):
        raise InputError('report_destination_is_protected')
    for item in apps:
        selected = Path(item).resolve()
        if resolved == selected or resolved.is_relative_to(selected):
            raise InputError('report_destination_overlaps_app')
    return resolved


def write_report(destination, report):
    """Replace a complete same-directory JSON file; preserve the old report on error."""
    data = (json.dumps(report, ensure_ascii=True, indent=2) + '\n').encode('utf-8')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', prefix='.compatibility-', suffix='.tmp',
                                         dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='Explicit JSON report destination')
    parser.add_argument('--app', action='append', default=[], type=Path,
                        help='Explicit app bundle or Mach-O executable; max 16; never launched')
    arguments = parser.parse_args(argv)
    if len(arguments.app) > MAX_APPS:
        parser.error('At most 16 explicit apps may be checked.')
    try:
        destination = report_destination(arguments.out, arguments.app)
    except (InputError, OSError, ValueError):
        parser.error('Report destination must be a JSON file outside apps, EFI and system folders.')
    report = collect(arguments.app)
    try:
        write_report(destination, report)
    except (OSError, ValueError):
        print('Kompatibilitaetsbericht konnte nicht gespeichert werden.', file=sys.stderr)
        return 3
    print('Kompatibilitaetsbericht gespeichert; Status: ' + report['state'])
    return 2 if report['state'] == 'unsupported-platform' else 0


if __name__ == '__main__':
    raise SystemExit(main())
