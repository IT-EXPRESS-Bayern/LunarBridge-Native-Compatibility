# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 IT-EXPRESS Bayern and LunarBridge contributors.
"""Adversarial Mach-O symbol contracts, not a hardware driver acceptance test."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import graphics_interfaces as checker


def macho(imports=(), exports=(), extra=b'', kind=11, cpu=0x01000007, subtype=3,
          endian='<', wide=True, symbol_table=True, export_data=None):
    header_bytes = 32 if wide else 28
    command_bytes = (24 if symbol_table else 0) + len(extra) + (16 if export_data is not None else 0)
    symbol_offset = header_bytes + command_bytes
    strings = bytearray(b'\0')
    symbols = bytearray()
    for symbol_type, names in ((1, imports), (3, exports)):
        for name in names:
            offset = len(strings)
            strings.extend(name + b'\0')
            symbols.extend(struct.pack(endian + ('IBBHQ' if wide else 'IBBHI'), offset, symbol_type, 0, 0, 0))
    commands = b''
    if symbol_table:
        commands += struct.pack(endian + '6I', 2, 24, symbol_offset,
                                len(imports) + len(exports), symbol_offset + len(symbols), len(strings))
    if export_data is not None:
        commands += struct.pack(endian + '4I', 0x80000033, 16,
                               symbol_offset + len(symbols) + len(strings), len(export_data))
    commands += extra
    values = [0xFEEDFACF if wide else 0xFEEDFACE, cpu, subtype, kind,
              int(symbol_table) + int(export_data is not None) + bool(extra), command_bytes, 0]
    if wide:
        values.append(0)
    return struct.pack(endian + ('8I' if wide else '7I'), *values) + commands + symbols + strings + (export_data or b'')


def fat(items, endian='>', wide=False):
    entry_size = 32 if wide else 20
    offset = 8 + entry_size * len(items)
    table, content = b'', b''
    for cpu, subtype, data in items:
        values = [cpu, subtype, offset, len(data), 0] + ([0] if wide else [])
        table += struct.pack(endian + ('IIQQII' if wide else 'IIIII'), *values)
        content += data
        offset += len(data)
    return struct.pack(endian + 'II', 0xCAFEBABF if wide else 0xCAFEBABE, len(items)) + table + content


def trie(name, terminal=b'\0\1'):
    # Test names are short enough for one-byte child offsets.
    root = b'\0\1' + name + b'\0'
    return root + bytes([len(root) + 1]) + bytes([len(terminal)]) + terminal + b'\0'


class GraphicsInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.serial = 0

    def tearDown(self):
        self.temporary.cleanup()

    def file(self, data):
        self.serial += 1
        target = self.root / ('private-project-' + str(self.serial))
        target.write_bytes(data)
        return target

    def slice(self, report, index=0):
        return report['files'][index]['slices'][0]

    def test_imports_are_compared_by_exact_symbol_and_provider_architecture(self):
        symbol = checker.COPY_MAPPER
        consumer = self.file(macho(imports=[symbol]))
        arm = self.file(macho(exports=[symbol], cpu=0x0100000C, subtype=0, kind=6))
        report = checker.collect([consumer], [arm])
        item = self.slice(report)['interfaces']['IOMapper.copyMapperForDevice']
        self.assertEqual(item['imports_observed'], 1)
        self.assertEqual(item['exact_imports_found_in_selected_provider_exports'], 0)
        intel = self.file(macho(exports=[symbol], kind=6))
        report = checker.collect([consumer], [intel])
        self.assertEqual(self.slice(report)['interfaces']['IOMapper.copyMapperForDevice']['provider_resolution'],
                         'exact_symbol_names_observed')
        self.assertFalse(report['function_signature_abi_verified'])
        self.assertFalse(report['kext_loadability_verified'])

    def test_same_method_name_with_different_parameter_type_does_not_resolve(self):
        consumer = self.file(macho(imports=[checker.COPY_MAPPER]))
        different = checker.COPY_MAPPER.replace(b'P9IOService', b'P12IOUserClient')
        provider = self.file(macho(exports=[different], kind=6))
        item = self.slice(checker.collect([consumer], [provider]))['interfaces']['IOMapper.copyMapperForDevice']
        self.assertEqual(item['imports_without_selected_provider_export'], 1)

    def test_missing_or_stripped_tables_are_unverified_instead_of_an_os_absence_claim(self):
        selected = self.file(macho(symbol_table=False))
        report = checker.collect([selected])
        self.assertFalse(self.slice(report)['symbol_table_present'])
        self.assertEqual(self.slice(report)['imports_observed'], 0)
        self.assertIn('ABSENCE_FROM_EXAMINED_TABLES_DOES_NOT_PROVE_OS_ABSENCE', report['limitations'])
        self.assertFalse(report['metal_driver_registration_verified'])

    def test_direct_export_trie_resolves_an_import_without_nlist_exports(self):
        name = b'_IOSurfaceCreate'
        consumer = self.file(macho(imports=[name], kind=2))
        provider = self.file(macho(symbol_table=False, kind=6, export_data=trie(name)))
        report = checker.collect([consumer], [provider])
        self.assertTrue(self.slice(report, 1)['export_trie_present'])
        self.assertEqual(self.slice(report)['interfaces']['IOSurface']['exact_imports_found_in_selected_provider_exports'], 1)

    def test_reexport_name_alone_is_not_treated_as_a_direct_provider(self):
        name = b'_IOSurfaceCreate'
        consumer = self.file(macho(imports=[name], kind=2))
        provider = self.file(macho(kind=6, symbol_table=False, export_data=trie(name, b'\x08\x01\0')))
        report = checker.collect([consumer], [provider])
        self.assertEqual(self.slice(report, 1)['indirect_exports_unresolved'], 1)
        self.assertEqual(self.slice(report)['interfaces']['IOSurface']['provider_resolution'], 'unverified')

    def test_cyclic_truncated_and_overflowing_export_tries_fail_boundedly(self):
        payloads = [b'\0\1a\0\0', b'\x80', b'\xff' * 10 + b'\0',
                    b'\0\1a\0\x7f', trie(b'_IOSurfaceCreate')[:-1],
                    b'\0\1a\0\x05\0\1b\0\x05']
        for payload in payloads:
            report = checker.collect([self.file(macho(export_data=payload))])
            self.assertEqual(report['files'][0]['state'], 'unverified')

    def test_dyld_chained_imports_are_flagged_as_unexamined(self):
        extra = struct.pack('<4I', 0x80000034, 16, 0, 1)
        report = checker.collect([self.file(macho(imports=[b'_MTLCopyAllDevices'], extra=extra))])
        self.assertTrue(self.slice(report)['other_import_encoding_unexamined'])
        self.assertEqual(self.slice(report)['interfaces']['Metal']['imports_observed'], 1)

    def test_opposite_endian_and_32bit_symbols_cannot_resolve_intel64(self):
        symbol = b'_IOSurfaceCreate'
        consumer = self.file(macho(imports=[symbol], endian='>'))
        provider = self.file(macho(exports=[symbol], endian='>', wide=False, cpu=7, kind=6))
        report = checker.collect([consumer], [provider])
        self.assertEqual(self.slice(report)['interfaces']['IOSurface']['imports_without_selected_provider_export'], 1)
        self.assertEqual(self.slice(report, 1)['architecture'], 'i386')

    def test_universal64_provider_uses_only_matching_intel_slice(self):
        name = b'_IOSurfaceCreate'
        consumer = self.file(macho(imports=[name]))
        provider = self.file(fat([(0x0100000C, 0, macho(cpu=0x0100000C, subtype=0, kind=6)),
                                  (0x01000007, 3, macho(exports=[name], kind=6))], wide=True, endian='<'))
        report = checker.collect([consumer], [provider])
        self.assertEqual(self.slice(report)['interfaces']['IOSurface']['provider_resolution'], 'exact_symbol_names_observed')

    def test_fat_overlap_and_header_cpu_disagreement_are_rejected(self):
        data = bytearray(fat([(0x01000007, 3, macho()), (0x0100000C, 0, macho(cpu=0x0100000C, subtype=0))]))
        for offset, value in ((8, 0x0100000C), (36, 48), (24, 32)):
            changed = bytearray(data)
            struct.pack_into('>I', changed, offset, value)
            report = checker.collect([self.file(changed)])
            self.assertEqual(report['files'][0]['state'], 'unverified')

    def test_symbol_table_offsets_counts_and_unterminated_names_are_rejected(self):
        original = macho(imports=[b'_IOSurfaceCreate'])
        for offset, value in ((40, 0xFFFFFFFF), (44, checker.MAX_SYMBOLS + 1),
                              (48, 0xFFFFFFFF), (52, checker.MAX_STRING_BYTES + 1), (56, 9999)):
            corrupt = bytearray(original)
            struct.pack_into('<I', corrupt, offset, value)
            self.assertEqual(checker.collect([self.file(corrupt)])['files'][0]['state'], 'unverified')
        self.assertEqual(checker.collect([self.file(original[:-1])])['files'][0]['state'], 'unverified')

    def test_section_definition_requires_a_valid_segment_section(self):
        data = bytearray(macho(exports=[b'_IOSurfaceCreate']))
        data[60] = 15  # N_EXT | N_SECT, but no LC_SEGMENT section exists.
        data[61] = 1
        report = checker.collect([self.file(data)])
        self.assertEqual(report['files'][0]['code'], 'symbol_section_invalid')

    def test_private_and_local_definitions_are_not_export_providers(self):
        name = b'_IOSurfaceCreate'
        consumer = self.file(macho(imports=[name]))
        for symbol_type in (2, 0x13):
            data = bytearray(macho(exports=[name], kind=6))
            data[60] = symbol_type
            report = checker.collect([consumer], [self.file(data)])
            self.assertEqual(self.slice(report)['interfaces']['IOSurface']['provider_resolution'], 'unverified')

    def test_kernel_collection_and_object_file_are_not_silently_flattened(self):
        for kind in (12, 1):
            report = checker.collect([self.file(macho(kind=kind))])
            self.assertEqual(report['files'][0]['state'], 'unverified')
        self.assertEqual(checker.collect([self.file(macho(kind=12))])['files'][0]['code'],
                         'kernel_fileset_requires_specialized_extraction')

    def test_reports_emit_only_fixed_labels_and_hashes_without_private_symbols(self):
        imports = [b'__ZN12IODMACommand17withSpecificationEPv', b'__ZTV9IOService',
                   b'_private-user-name-session-secret', b'_IOSurfaceCreate']
        selected = self.file(macho(imports=imports, exports=[b'_private-project-export']))
        report = checker.collect([selected])
        self.assertEqual(self.slice(report)['interfaces']['IODMACommand']['imports_observed'], 1)
        self.assertEqual(self.slice(report)['interfaces']['IOService']['imports_observed'], 1)
        text = json.dumps(report)
        for private in ('private-user-name', 'private-project', 'session-secret', str(self.root)):
            self.assertNotIn(private, text)
        self.assertEqual(len(report['files'][0]['sha256']), 64)

    def test_special_files_are_refused_without_open_and_selected_binaries_are_never_run(self):
        with mock.patch.object(checker.os, 'open') as opener:
            report = checker.collect([self.root])
        opener.assert_not_called()
        self.assertEqual(report['files'][0]['code'], 'not_regular_file')
        if hasattr(os, 'mkfifo'):
            fifo = self.root / 'selected-fifo'
            os.mkfifo(fifo)
            self.assertEqual(checker.collect([fifo])['files'][0]['code'], 'not_regular_file')
        with mock.patch('subprocess.run', side_effect=AssertionError('No process allowed')), \
             mock.patch.object(Path, 'rglob', side_effect=AssertionError('No scan allowed')):
            report = checker.collect([self.file(macho())])
        self.assertEqual(report['state'], 'static-file-analysis')

    def test_resource_limits_apply_before_reading_large_files(self):
        path = self.file(b'')
        with path.open('wb') as handle:
            handle.truncate(checker.MAX_FILE_BYTES + 1)
        report = checker.collect([path])
        self.assertEqual(report['files'][0]['code'], 'selected_file_size_limit')
        with self.assertRaisesRegex(checker.InputError, '^selected_total_size_limit$'):
            checker.collect([path, path, path])
        with self.assertRaises(checker.InputError):
            checker.collect([path] * 17)

    def test_cli_write_failure_preserves_existing_report_and_prints_no_private_path(self):
        selected = self.file(macho())
        destination = self.root / 'private-user-report.json'
        destination.write_bytes(b'original report')
        stderr, stdout = io.StringIO(), io.StringIO()
        with mock.patch('native_compatibility.os.replace', side_effect=OSError(str(destination))), \
             redirect_stderr(stderr), redirect_stdout(stdout):
            status = checker.main(['--consumer', str(selected), '--out', str(destination)])
        self.assertEqual(status, 3)
        self.assertEqual(destination.read_bytes(), b'original report')
        self.assertNotIn('private', stderr.getvalue() + stdout.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())

    def test_published_source_export_contract_does_not_certify_delivered_binary_exports(self):
        consumer = self.file(macho(imports=[checker.COPY_MAPPER]))
        declarations = self.file(checker.COPY_MAPPER + b'\n_some_alias : _underlying_symbol\n')
        report = checker.collect([consumer], [], [declarations])
        item = self.slice(report)['interfaces']['IOMapper.copyMapperForDevice']
        self.assertEqual(item['imports_found_in_selected_source_export_contracts'], 1)
        self.assertEqual(item['exact_imports_found_in_selected_provider_exports'], 0)
        self.assertEqual(item['provider_resolution'], 'unverified')
        self.assertFalse(report['files'][1]['delivered_os_exports_verified'])

    def test_export_contract_malformed_alias_binary_content_or_oversize_is_rejected(self):
        for raw in (b'_valid : _alias : _invalid\n', b'/Users/private-data\n', b'\x80\x90',
                    b'# comment only\n', b'_' * (checker.MAX_EXPORT_LIST_BYTES + 1)):
            report = checker.collect([], [], [self.file(raw)])
            self.assertEqual(report['files'][0]['state'], 'unverified')
            self.assertNotIn('private-data', json.dumps(report))

    def test_output_cannot_overwrite_a_selected_export_contract(self):
        contract = self.root / 'source.json'
        contract.write_bytes(b'_IOSurfaceCreate\n')
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as exit_code:
            checker.main(['--export-list', str(contract), '--out', str(contract)])
        self.assertEqual(exit_code.exception.code, 2)
        self.assertEqual(contract.read_bytes(), b'_IOSurfaceCreate\n')

    def test_repeated_long_symbol_names_have_an_aggregate_processing_limit(self):
        selected = self.file(macho(imports=[b'_IOSurfaceCreate', b'_MTLCopyAllDevices']))
        with mock.patch.object(checker, 'MAX_ACCUMULATED_NAME_BYTES', 20):
            report = checker.collect([selected])
        self.assertEqual(report['files'][0]['code'], 'symbol_total_name_limit')

    def test_version_specific_accelerator_interface_names_are_detectable_without_abi_claims(self):
        selected = self.file(macho(imports=[b'__ZTV22IOGraphicsAccelerator2',
                                            b'__ZN16IntelAccelerator5startEP9IOService']))
        report = checker.collect([selected])
        self.assertEqual(self.slice(report)['interfaces']['IOGraphicsAccelerator2']['imports_observed'], 1)
        self.assertEqual(self.slice(report)['interfaces']['IntelAccelerator']['imports_observed'], 1)
        self.assertFalse(report['function_signature_abi_verified'])

    def test_unobserved_reserved_padslots_are_distinguished_from_provider_absence(self):
        imports = [b'__ZN9IOService19_RESERVEDIOService2Ev', b'__ZN9IOService5startEPS_']
        report = checker.collect([self.file(macho(imports=imports))])
        item = self.slice(report)['interfaces']['IOService']
        self.assertEqual(item['source_contract_unobserved_reserved_padslot_imports'], 1)
        self.assertEqual(item['imports_without_selected_provider_export'], 2)
        self.assertFalse(report['kext_loadability_verified'])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(GraphicsInterfaceTests))
    (ROOT / 'tests/graphics-interface-test-report.json').write_text(json.dumps({
        'test_type': 'Mach-O imports/exports, malformed trie/table boundaries and privacy; no driver execution',
        'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'successful': result.wasSuccessful(),
        'native_macos_hardware_tests': 0, 'selected_programs_executed': 0, 'system_policy_changes': 0,
    }, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() else 1)
