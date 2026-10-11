# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 IT-EXPRESS Bayern and LunarBridge contributors.
"""Inspect explicitly selected Mach-O imports/exports; never load or execute them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

from native_compatibility import (FAT_MAGIC, THIN_MAGIC, InputError, architecture,
                                  open_regular, report_destination, write_report)

MAX_FILES = 16
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SYMBOLS = 262144
MAX_STRING_BYTES = 8 * 1024 * 1024
MAX_TRIE_BYTES = 8 * 1024 * 1024
MAX_TRIE_NODES = 65536
MAX_NAME_BYTES = 4096
MAX_ACCUMULATED_NAME_BYTES = 16 * 1024 * 1024
MAX_EXPORT_LIST_BYTES = 1024 * 1024
MACHO_KINDS = {2: 'executable', 6: 'dylib', 8: 'bundle', 11: 'kernel_bundle'}
COPY_MAPPER = b'__ZN8IOMapper19copyMapperForDeviceEP9IOService'
CLASS_NAMES = ('IOService', 'IOUserClient', 'IOBufferMemoryDescriptor', 'IOMemoryDescriptor',
               'IOMapper', 'IODMACommand', 'IOFramebuffer', 'IOAccelerator',
               'IOGraphicsAccelerator2', 'IOAccelDevice2', 'IOAccelContext2', 'IOAccelSharedUserClient2',
               'IOAccelCommandQueue', 'IOAccelCommandBufferPool2', 'IntelAccelerator',
               'IGAccelCommandQueue', 'IntelMTLRenderFunctions')
CLASS_PATTERNS = {name: re.compile(rb'^_+Z(?:N[KVR]*|TV|TI|TS)' +
                                 str(len(name)).encode() + name.encode() + rb'(?=[A-Z0-9]|$)')
                  for name in CLASS_NAMES}
PUBLIC_FUNCTIONS = {'MTLCopyAllDevices', 'MTLCreateSystemDefaultDevice', 'IOSurfaceCreate',
                    'IOSurfaceLookup', 'IOSurfaceGetID', 'IOSurfaceCreateMachPort',
                    'IOSurfaceLookupFromMachPort', 'IORegistryEntryIDMatching',
                    'IORegistryEntryGetRegistryEntryID', 'IOServiceGetMatchingService'}
FAMILIES = (*CLASS_NAMES, 'IOMapper.copyMapperForDevice', 'IOSurface', 'Metal', 'IOKitRegistry')


def symbol_family(name):
    """Report only fixed interface labels, never arbitrary selected-file symbols."""
    if name == COPY_MAPPER:
        return 'IOMapper.copyMapperForDevice'
    for label, pattern in CLASS_PATTERNS.items():
        if pattern.match(name):
            return label
    text = name.removeprefix(b'_')
    if text in {item.encode() for item in PUBLIC_FUNCTIONS}:
        if text.startswith(b'IOSurface'):
            return 'IOSurface'
        if text.startswith(b'MTL'):
            return 'Metal'
        return 'IOKitRegistry'
    return None


def region(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise InputError('macho_range_invalid')
    return memoryview(data)[offset:offset + size]


def uleb(data, offset, end):
    result = 0
    for shift in range(0, 70, 7):
        if offset >= end:
            raise InputError('export_trie_uleb_truncated')
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise InputError('export_trie_uleb_overflow')
        result |= (byte & 127) << shift
        if not byte & 128:
            return result, offset
    raise InputError('export_trie_uleb_overflow')


def export_trie(data):
    """Recognize direct regular/absolute exports; reexports need another provider."""
    if not data:
        return set(), set()
    if len(data) > MAX_TRIE_BYTES:
        raise InputError('export_trie_limit')
    exports, indirect = set(), set()
    stack = [(0, b'', ())]
    visits, name_bytes = 0, 0
    while stack:
        offset, name, ancestors = stack.pop()
        visits += 1
        if visits > MAX_TRIE_NODES or len(ancestors) > 256:
            raise InputError('export_trie_node_limit')
        if offset in ancestors or offset >= len(data):
            raise InputError('export_trie_cycle_or_range')
        terminal_size, position = uleb(data, offset, len(data))
        terminal_end = position + terminal_size
        if terminal_end >= len(data):
            raise InputError('export_trie_terminal_invalid')
        if terminal_size:
            flags, item_position = uleb(data, position, terminal_end)
            if flags & ~0x1F or flags & 3 == 3 or not name:
                raise InputError('export_trie_flags_or_name_invalid')
            if flags & 8:  # EXPORT_SYMBOL_FLAGS_REEXPORT
                _, item_position = uleb(data, item_position, terminal_end)
                terminator = data.find(b'\0', item_position, terminal_end)
                if terminator < 0 or terminator != terminal_end - 1:
                    raise InputError('export_trie_reexport_invalid')
                indirect.add(name)
            else:
                _, item_position = uleb(data, item_position, terminal_end)
                if flags & 16:  # EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
                    _, item_position = uleb(data, item_position, terminal_end)
                if item_position != terminal_end:
                    raise InputError('export_trie_terminal_invalid')
                if flags & 3 in (0, 2):
                    exports.add(name)
                else:
                    indirect.add(name)
        child_count = data[terminal_end]
        position = terminal_end + 1
        edges = set()
        for _ in range(child_count):
            terminator = data.find(b'\0', position)
            if terminator < 0 or terminator == position:
                raise InputError('export_trie_edge_invalid')
            edge = data[position:terminator]
            name_bytes += len(name) + len(edge)
            if name_bytes > MAX_ACCUMULATED_NAME_BYTES:
                raise InputError('export_trie_total_name_limit')
            if len(name) + len(edge) > MAX_NAME_BYTES or edge in edges:
                raise InputError('export_trie_name_or_edge_invalid')
            edges.add(edge)
            child, position = uleb(data, terminator + 1, len(data))
            if child == 0:
                raise InputError('export_trie_cycle_or_range')
            stack.append((child, name + edge, ancestors + (offset,)))
    return exports, indirect


def thin_slice(data, outer_cpu=None, outer_subtype=None):
    magic = bytes(region(data, 0, 4))
    if magic not in THIN_MAGIC:
        raise InputError('slice_not_macho')
    endian, wide = THIN_MAGIC[magic]
    header_bytes = 32 if wide else 28
    fields = struct.unpack(endian + ('8I' if wide else '7I'), region(data, 0, header_bytes))
    cpu, subtype, kind, count, command_bytes = fields[1:6]
    if kind == 12:
        raise InputError('kernel_fileset_requires_specialized_extraction')
    if kind not in MACHO_KINDS or bool(cpu & 0x01000000) != wide:
        raise InputError('macho_kind_or_cpu_invalid')
    if outer_cpu is not None and (cpu, subtype) != (outer_cpu, outer_subtype):
        raise InputError('fat_cpu_mismatch')
    if (wide and fields[7]) or count > 4096 or command_bytes > MAX_STRING_BYTES:
        raise InputError('load_command_limit')
    commands = region(data, header_bytes, command_bytes)
    symbol_table, trie_range = None, None
    section_count = 0
    position = 0
    other_import_encoding = False
    for _ in range(count):
        block = region(commands, position, 8)
        command, size = struct.unpack(endian + 'II', block)
        if size < 8 or size % (8 if wide else 4):
            raise InputError('load_command_invalid')
        block = region(commands, position, size)
        if command in (1, 0x19):
            header, section_bytes, count_offset = (72, 80, 64) if command == 0x19 else (56, 68, 48)
            if size < header or (command == 0x19) != wide:
                raise InputError('segment_command_invalid')
            segment_sections = struct.unpack_from(endian + 'I', block, count_offset)[0]
            if size != header + segment_sections * section_bytes:
                raise InputError('segment_sections_invalid')
            section_count += segment_sections
            if section_count > 255:
                raise InputError('section_count_limit')
        elif command == 2:
            if size != 24 or symbol_table is not None:
                raise InputError('symbol_table_command_invalid')
            symbol_table = struct.unpack_from(endian + '4I', block, 8)
        elif command == 0x80000033:
            if size != 16 or trie_range is not None:
                raise InputError('export_trie_command_invalid')
            trie_range = struct.unpack_from(endian + 'II', block, 8)
        elif command in (0x22, 0x80000022):
            if size != 48:
                raise InputError('dyld_info_command_invalid')
            values = struct.unpack_from(endian + '10I', block, 8)
            other_import_encoding |= any(values[index] for index in (3, 5, 7))
            if values[9]:
                if trie_range is not None:
                    raise InputError('export_trie_command_invalid')
                trie_range = values[8:10]
        elif command == 0x80000034:
            if size != 16:
                raise InputError('chained_fixups_command_invalid')
            offset, length = struct.unpack_from(endian + 'II', block, 8)
            region(data, offset, length)
            other_import_encoding |= bool(length)
        position += size
    if position != len(commands):
        raise InputError('load_command_size_mismatch')
    imports, exports, indirect = set(), set(), set()
    symbol_count = 0
    if symbol_table is not None:
        offset, symbol_count, string_offset, string_bytes = symbol_table
        if symbol_count > MAX_SYMBOLS or string_bytes > MAX_STRING_BYTES:
            raise InputError('symbol_table_limit')
        symbols = region(data, offset, symbol_count * (16 if wide else 12))
        strings = bytes(region(data, string_offset, string_bytes))
        name_bytes = 0
        for index in range(symbol_count):
            name_offset, symbol_type, section, description, value = struct.unpack_from(
                endian + ('IBBHQ' if wide else 'IBBHI'), symbols, index * (16 if wide else 12))
            if symbol_type & 0xE0 or not name_offset:
                continue
            if name_offset >= len(strings):
                raise InputError('symbol_string_range_invalid')
            terminator = strings.find(b'\0', name_offset, min(len(strings), name_offset + MAX_NAME_BYTES + 1))
            if terminator < 0:
                raise InputError('symbol_string_unterminated_or_limit')
            name = strings[name_offset:terminator]
            name_bytes += len(name)
            if name_bytes > MAX_ACCUMULATED_NAME_BYTES:
                raise InputError('symbol_total_name_limit')
            if not symbol_type & 1:
                continue
            basic_type = symbol_type & 0x0E
            if basic_type == 0 and value == 0:
                imports.add(name)
            elif basic_type in (2, 14):
                if basic_type == 14 and not 1 <= section <= section_count:
                    raise InputError('symbol_section_invalid')
                if not symbol_type & 0x10:
                    exports.add(name)
            elif basic_type == 10:
                indirect.add(name)
    if trie_range is not None:
        offset, length = trie_range
        if length > MAX_TRIE_BYTES:
            raise InputError('export_trie_limit')
        direct, aliases = export_trie(bytes(region(data, offset, length)))
        exports.update(direct)
        indirect.update(aliases)
    return {'architecture': architecture(cpu, subtype), 'kind': MACHO_KINDS[kind],
            'symbol_table_present': symbol_table is not None, 'symbol_entry_count': symbol_count,
            'export_trie_present': trie_range is not None,
            'other_import_encoding_unexamined': other_import_encoding,
            'imports': imports, 'exports': exports, 'indirect': indirect}


def inspect_file(path):
    with open_regular(path) as handle:
        before = os.fstat(handle.fileno())
        if before.st_size > MAX_FILE_BYTES:
            raise InputError('selected_file_size_limit')
        data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise InputError('input_changed_during_read')
    magic = bytes(region(data, 0, 4))
    slices = []
    if magic in FAT_MAGIC:
        endian, wide = FAT_MAGIC[magic]
        count = struct.unpack(endian + 'I', region(data, 4, 4))[0]
        if not 1 <= count <= 16:
            raise InputError('architecture_count_invalid')
        entry_bytes = 32 if wide else 20
        table_end = 8 + count * entry_bytes
        entries = region(data, 8, count * entry_bytes)
        occupied, cpus = [], set()
        for index in range(count):
            values = struct.unpack_from(endian + ('IIQQII' if wide else 'IIIII'), entries, index * entry_bytes)
            cpu, subtype, offset, size, alignment = values[:5]
            if alignment > 31 or offset < table_end or offset % (1 << alignment) or size < 28 or \
                    (wide and values[5]) or (cpu, subtype) in cpus:
                raise InputError('fat_slice_invalid')
            block = region(data, offset, size)
            if any(offset < start + length and start < offset + size for start, length in occupied):
                raise InputError('fat_slices_overlap')
            occupied.append((offset, size))
            cpus.add((cpu, subtype))
            slices.append(thin_slice(block, cpu, subtype))
    else:
        slices.append(thin_slice(data))
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'slices': slices}


def inspect_export_list(path):
    """Parse a selected XNU-style source export contract, not a runtime binary."""
    with open_regular(path) as handle:
        before = os.fstat(handle.fileno())
        if before.st_size > MAX_EXPORT_LIST_BYTES:
            raise InputError('export_list_size_limit')
        raw = handle.read(MAX_EXPORT_LIST_BYTES + 1)
        after = os.fstat(handle.fileno())
        if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise InputError('input_changed_during_read')
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise InputError('export_list_encoding_invalid') from None
    exports = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        names = [name.strip() for name in line.split(':')]
        if len(names) > 2 or any(not re.fullmatch(r'_[A-Za-z0-9_.$]{1,4095}', name) for name in names):
            raise InputError('export_list_entry_invalid')
        exports.add(names[0].encode())
        if len(exports) > MAX_SYMBOLS:
            raise InputError('export_list_entry_limit')
    if not exports:
        raise InputError('export_list_empty')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'exports': exports}


def family_report(item, providers, declarations):
    result = {}
    for family in FAMILIES:
        imports = {name for name in item['imports'] if symbol_family(name) == family}
        exports = {name for name in item['exports'] if symbol_family(name) == family}
        matches = imports & providers
        result[family] = {'imports_observed': len(imports), 'exports_observed': len(exports),
                          'exact_imports_found_in_selected_provider_exports': len(matches),
                          'imports_found_in_selected_source_export_contracts': len(imports & declarations),
                          'source_contract_unobserved_reserved_padslot_imports': sum(
                              b'_RESERVED' in name for name in imports - declarations),
                          'imports_without_selected_provider_export': len(imports - providers),
                          'provider_resolution': 'not_requested_by_examined_imports' if not imports else
                          'exact_symbol_names_observed' if len(matches) == len(imports) else 'unverified'}
    return result


def collect(consumers=(), providers=(), export_lists=()):
    paths = [*consumers, *providers, *export_lists]
    if not paths or len(paths) > MAX_FILES:
        raise InputError('selection_count_invalid')
    # Bound total input before any content is read. No directory or app scanning.
    total = 0
    for path in paths:
        try:
            total += min(Path(path).stat().st_size, MAX_FILE_BYTES)
        except OSError:
            pass
    if total > MAX_TOTAL_BYTES:
        raise InputError('selected_total_size_limit')
    parsed, selections, declared_exports = [], [], set()
    for index, path in enumerate(paths, 1):
        role = 'consumer' if index <= len(consumers) else \
               'provider' if index <= len(consumers) + len(providers) else 'source_export_contract'
        summary = {'selection_index': index, 'role': role, 'state': 'unverified'}
        try:
            if role == 'source_export_contract':
                item = inspect_export_list(path)
                declared_exports.update(item['exports'])
                summary.update({'state': 'source_export_contract_observed', 'sha256': item['sha256'],
                                'bytes': item['bytes'], 'declared_export_count': len(item['exports']),
                                'delivered_os_exports_verified': False})
            else:
                item = inspect_file(path)
                summary.update({'state': 'static_symbols_observed', 'sha256': item['sha256'], 'bytes': item['bytes']})
                parsed.append((summary, item))
        except InputError as exc:
            summary['code'] = str(exc)
        except (OSError, ValueError, OverflowError, struct.error):
            summary['code'] = 'selected_input_unreadable_or_invalid'
        selections.append(summary)
    provider_exports = set()
    for summary, file in parsed:
        if summary['role'] == 'provider':
            for item in file['slices']:
                if item['architecture'] == 'x86_64':
                    provider_exports.update(item['exports'])
    for summary, file in parsed:
        summary['slices'] = []
        for item in file['slices']:
            safe = {key: value for key, value in item.items() if key not in ('imports', 'exports', 'indirect')}
            safe.update({'imports_observed': len(item['imports']), 'exports_observed': len(item['exports']),
                         'indirect_exports_unresolved': len(item['indirect']),
                         'interfaces': family_report(item, provider_exports if item['architecture'] == 'x86_64' else set(),
                                                     declared_exports if item['architecture'] == 'x86_64' else set())})
            summary['slices'].append(safe)
    return {'schema': 1, 'state': 'static-file-analysis', 'target_architecture': 'x86_64',
            'native_runtime_checked': False, 'kext_loadability_verified': False,
            'function_signature_abi_verified': False, 'gpu_execution_verified': False,
            'metal_driver_registration_verified': False, 'firmware_secure_boot_verified': False,
            'files': selections, 'limitations': ['SYMBOL_NAMES_DO_NOT_VERIFY_CXX_RETURN_TYPES_OR_VTABLES',
            'ABSENCE_FROM_EXAMINED_TABLES_DOES_NOT_PROVE_OS_ABSENCE',
            'RESERVED_VTABLE_SLOTS_REQUIRE_NATIVE_KEXT_LINKER_PATCHING_CHECKS',
            'DYLD_BIND_OPCODES_CHAINED_IMPORTS_AND_OBJC_SELECTORS_NOT_PARSED',
            'REEXPORT_AND_KERNEL_FILESET_OR_SHARED_CACHE_EXTRACTION_REQUIRED',
            'SELECTED_SOURCE_EXPORT_CONTRACTS_DO_NOT_PROVE_DELIVERED_OS_EXPORTS',
            'PROVIDER_VERSION_AND_KEXT_DEPENDENCY_POLICY_REQUIRE_SEPARATE_CHECKS']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consumer', action='append', default=[], type=Path,
                        help='Explicit Mach-O executable, bundle or kext executable; never loaded')
    parser.add_argument('--provider', action='append', default=[], type=Path,
                        help='Explicit extracted Mach-O provider; x86_64 export comparison only')
    parser.add_argument('--export-list', action='append', default=[], type=Path,
                        help='Explicit XNU-style source export contract; no delivered-OS export proof')
    parser.add_argument('--out', required=True, type=Path, help='Explicit sanitized JSON destination')
    args = parser.parse_args(argv)
    paths = [*args.consumer, *args.provider, *args.export_list]
    if not paths or len(paths) > MAX_FILES:
        parser.error('Select between 1 and 16 explicit files.')
    try:
        destination = report_destination(args.out, paths)
        report = collect(args.consumer, args.provider, args.export_list)
    except (InputError, OSError, ValueError):
        parser.error('Invalid selection or report destination.')
    try:
        write_report(destination, report)
    except (OSError, ValueError):
        print('Schnittstellenbericht konnte nicht gespeichert werden.', file=sys.stderr)
        return 3
    print('Statischer Schnittstellenbericht gespeichert; keine Datei ausgefuehrt.')
    return 2 if any(item['state'] == 'unverified' for item in report['files']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
