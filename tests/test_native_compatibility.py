# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2026 IT-EXPRESS Bayern and LunarBridge contributors.
"""Synthetic executable and failure tests; no native target device proof."""
import ctypes as c
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_compatibility as checker


def encoded_version(major, minor=0, patch=0):
    return (major << 16) | (minor << 8) | patch


def binary(cpu=0x01000007, subtype=3, minimum=(13, 0, 0), target=1,
           libraries=(), endian='<', wide=True, extra=b''):
    commands = struct.pack(endian + '6I', 0x32, 24, target, encoded_version(*minimum),
                           encoded_version(26), 0)
    for name in libraries:
        raw = name.encode() + b'\0'
        size = (24 + len(raw) + (7 if wide else 3)) & (-8 if wide else -4)
        commands += struct.pack(endian + '6I', 0xC, size, 24, 0, 0, 0) + raw + bytes(size - 24 - len(raw))
    commands += extra
    magic = 0xFEEDFACF if wide else 0xFEEDFACE
    fields = [magic, cpu, subtype, 2, 1 + len(libraries) + bool(extra), len(commands), 0]
    if wide:
        fields.append(0)
    return struct.pack(endian + ('8I' if wide else '7I'), *fields) + commands


def universal(items, wide=False, endian='>'):
    entry_size = 32 if wide else 20
    offset = 8 + entry_size * len(items)
    entries, payload = [], b''
    for cpu, subtype, data in items:
        values = [cpu, subtype, offset, len(data), 0]
        if wide:
            values.append(0)
        entries.append(struct.pack(endian + ('IIQQII' if wide else 'IIIII'), *values))
        payload += data
        offset += len(data)
    return struct.pack(endian + 'II', 0xCAFEBABF if wide else 0xCAFEBABE, len(items)) + b''.join(entries) + payload


class NativeCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def executable(self, data):
        target = self.root / 'selected'
        target.write_bytes(data)
        return target

    def app(self, data, **values):
        root = self.root / 'Selected.app'
        (root / 'Contents/MacOS').mkdir(parents=True)
        (root / 'Contents/MacOS/Selected').write_bytes(data)
        metadata = {'CFBundleExecutable': 'Selected', 'LSMinimumSystemVersion': '13.0'}
        metadata.update(values)
        (root / 'Contents/Info.plist').write_bytes(plistlib.dumps(metadata))
        return root

    def test_windows_reports_unsupported_without_commands_or_app_reads(self):
        private = self.root / 'private-user-name/Personal.app'
        with mock.patch.object(checker.sys, 'platform', 'win32'), \
             mock.patch.object(checker, 'command') as commands, \
             mock.patch.object(checker, 'app_report') as apps, \
             mock.patch.object(checker, 'metal_report') as metal:
            report = checker.collect([private])
        commands.assert_not_called()
        apps.assert_not_called()
        metal.assert_not_called()
        self.assertEqual(report['state'], 'unsupported-platform')
        self.assertFalse(report['native_target_boot_verified'])
        self.assertEqual(report['apps'][0]['state'], 'not_checked')
        self.assertNotIn('private-user-name', json.dumps(report))

    def test_windows_cli_writes_reviewable_unsupported_report_and_exit_two(self):
        output = self.root / 'report.json'
        with mock.patch.object(checker.sys, 'platform', 'win32'):
            status = checker.main(['--out', str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.read_text())['state'], 'unsupported-platform')

    def test_intel_metadata_success_never_claims_launch_or_acceleration(self):
        report = checker.app_report(self.app(binary()), 1, '26.6.1')
        self.assertEqual(report['state'], 'metadata_prerequisites_satisfied')
        self.assertFalse(report['launch_tested'])
        self.assertFalse(report['plugins_and_transitive_dependencies_checked'])
        self.assertIn('RUNTIME_AND_DEPENDENCIES_UNVERIFIED', report['codes'])

    def test_arm_only_and_32bit_are_blocked_on_intel(self):
        for data in (binary(cpu=0x0100000C, subtype=0), binary(cpu=7, wide=False)):
            report = checker.app_report(self.executable(data), 1, '26.6.1')
            self.assertEqual(report['state'], 'blocked')
            self.assertEqual(report['codes'], ['NO_X86_64_EXECUTABLE'])

    def test_fat_arm_minimum_does_not_block_selected_intel_slice(self):
        data = universal([(0x0100000C, 0, binary(cpu=0x0100000C, subtype=0, minimum=(29, 0, 0))),
                          (0x01000007, 3, binary(minimum=(13, 0, 0)))])
        report = checker.app_report(self.executable(data), 1, '26.6.1')
        self.assertEqual(report['state'], 'metadata_prerequisites_satisfied')
        self.assertEqual(report['required_macos'], '13.0.0')

    def test_fat64_and_opposite_endian_headers_are_supported(self):
        data = universal([(0x01000007, 3, binary(endian='>'))], wide=True, endian='<')
        report = checker.app_report(self.executable(data), 1, '26.6.1')
        self.assertEqual(report['state'], 'metadata_prerequisites_satisfied')

    def test_os_minimum_is_maximum_of_header_and_bundle_constraints(self):
        root = self.app(binary(minimum=(26, 6, 2)), LSMinimumSystemVersion='13.0',
                        LSMinimumSystemVersionByArchitecture={'x86_64': '26.7', 'arm64': '29.0'})
        report = checker.app_report(root, 1, '26.6.1')
        self.assertEqual(report['state'], 'blocked')
        self.assertEqual(report['required_macos'], '26.7.0')
        self.assertIn('MACOS_VERSION_TOO_OLD', report['codes'])

    def test_ios_build_metadata_blocks_mac_execution(self):
        report = checker.app_report(self.executable(binary(target=2)), 1, '26.6.1')
        self.assertEqual(report['state'], 'blocked')
        self.assertEqual(report['codes'], ['NON_MACOS_EXECUTABLE'])

    def test_cpu_subtype_is_not_silently_assumed_compatible(self):
        report = checker.app_report(self.executable(binary(subtype=8)), 1, '26.6.1')
        self.assertEqual(report['state'], 'unverified')
        self.assertEqual(report['codes'], ['CPU_SUBTYPE_REQUIREMENTS_UNVERIFIED'])
        report = checker.app_report(self.executable(binary(subtype=9)), 1, '26.6.1')
        self.assertEqual(report['state'], 'blocked')

    def test_legacy_macos_minimum_and_missing_platform_stay_distinct(self):
        data = struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 2, 1, 16, 0, 0)
        data += struct.pack('<4I', 0x24, 16, encoded_version(10, 15), encoded_version(11))
        report = checker.app_report(self.executable(data), 1, '26.6.1')
        self.assertEqual(report['state'], 'metadata_prerequisites_satisfied')
        data = struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0)
        report = checker.app_report(self.executable(data), 1, '26.6.1')
        self.assertEqual(report['state'], 'unverified')
        self.assertIn('OS_REQUIREMENTS_INCOMPLETE', report['codes'])

    def test_only_allowlisted_framework_names_leave_private_link_paths(self):
        root = self.app(binary(libraries=('/System/Library/Frameworks/Metal.framework/Versions/A/Metal',
                                         '/System/Library/Frameworks/AGL.framework/Versions/A/AGL',
                                         '/Users/private-user-name/private-project/lib.dylib')),
                        CFBundleName='private-user-name', CFBundleIdentifier='private-session')
        report = checker.app_report(root, 1, '26.6.1')
        self.assertEqual(report['slices'][0]['linked_frameworks'], ['AGL', 'Metal'])
        self.assertIn('TAHOE_AGL_FUNCTIONS_HAVE_NO_EFFECT', report['codes'])
        encoded = json.dumps(report)
        self.assertNotIn('private', encoded)
        self.assertNotIn(str(root), encoded)

    def test_bundle_executable_path_escape_and_malformed_metadata_are_refused(self):
        root = self.app(binary(), CFBundleExecutable='../../private')
        report = checker.app_report(root, 1, '26.6.1')
        self.assertEqual(report['codes'], ['app_executable_invalid'])
        (root / 'Contents/Info.plist').write_text('invalid private-user-name metadata')
        report = checker.app_report(root, 1, '26.6.1')
        self.assertEqual(report['codes'], ['APP_INPUT_UNREADABLE_OR_INVALID'])
        self.assertNotIn('private', json.dumps(report))

    def test_selected_bundle_is_read_without_searching_or_launching_other_apps(self):
        root = self.app(binary())
        unrelated = self.root / 'Other.app'
        unrelated.mkdir()
        before = sorted(str(item.relative_to(self.root)) for item in self.root.rglob('*'))
        with mock.patch.object(checker.subprocess, 'run') as run, \
             mock.patch.object(Path, 'glob', side_effect=AssertionError('No search allowed')), \
             mock.patch.object(Path, 'rglob', side_effect=AssertionError('No search allowed')):
            report = checker.app_report(root, 1, '26.6.1')
        run.assert_not_called()
        self.assertEqual(report['state'], 'metadata_prerequisites_satisfied')
        self.assertEqual(before, sorted(str(item.relative_to(self.root)) for item in self.root.rglob('*')))

    def test_malformed_fat_offsets_cpu_mismatch_and_overlap_fail_closed(self):
        data = bytearray(universal([(0x01000007, 3, binary()), (0x0100000C, 0, binary(cpu=0x0100000C, subtype=0))]))
        for mutate in (lambda item: struct.pack_into('>I', item, 16, 0),
                       lambda item: struct.pack_into('>I', item, 8, 0x0100000C),
                       lambda item: struct.pack_into('>I', item, 36, 48),
                       lambda item: struct.pack_into('>I', item, 24, 32)):
            corrupt = bytearray(data)
            mutate(corrupt)
            with self.assertRaises(checker.InputError):
                checker.inspect_binary(self.executable(corrupt))

    def test_binary_truncation_resource_limits_and_width_mismatch_are_rejected(self):
        payloads = [b'MZprivate-user-name', binary()[:-1],
                    struct.pack('>II', 0xCAFEBABE, 17),
                    struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 2, 4097, 0, 0, 0),
                    struct.pack('<8I', 0xFEEDFACF, 7, 3, 2, 0, 0, 0, 0),
                    struct.pack('<8I', 0xFEEDFACF, 0x01000007, 3, 2, 1, 8, 0, 0) + struct.pack('<II', 0x32, 8)]
        for payload in payloads:
            with self.assertRaises(checker.InputError):
                checker.inspect_binary(self.executable(payload))

    def test_malformed_version_metadata_never_prints_raw_input(self):
        root = self.app(binary(), LSMinimumSystemVersion={'private-user-name': 'invalid'})
        report = checker.app_report(root, 1, '26.6.1')
        self.assertEqual(report['codes'], ['invalid_version'])
        self.assertNotIn('private', json.dumps(report))

    def test_policy_custom_output_does_not_certify_sip_or_firmware_secure_boot(self):
        report = checker.policy_report('sip', {'state': 'observed', 'data':
            b'System Integrity Protection status: unknown (Custom Configuration).\nprivate-user-name'})
        self.assertEqual(report['state'], 'custom_configuration')
        self.assertNotIn('private', json.dumps(report))
        report = checker.policy_report('sip', {'state': 'command_failed', 'data':
            b'System Integrity Protection status: enabled.'})
        self.assertEqual(report['state'], 'unknown')

    def test_command_timeout_and_output_limits_are_distinct_and_private(self):
        with mock.patch.object(checker.subprocess, 'run', side_effect=
                               checker.subprocess.TimeoutExpired(['private'], 15)):
            self.assertEqual(checker.command(['fixed'])['state'], 'timeout')
        with mock.patch.object(checker.subprocess, 'run', return_value=
                               mock.Mock(returncode=0, stdout=b'private' * 20000)):
            result = checker.command(['fixed'])
            self.assertEqual(result['state'], 'output_limit')
            self.assertEqual(result['data'], b'')

    def test_simulated_macos_no_metal_is_missing_and_execution_stays_unverified(self):
        def commands(arguments):
            if arguments[0].endswith('sw_vers'):
                return {'state': 'observed', 'data': b'26.6.1\n', 'returncode': 0}
            if arguments[0].endswith('pgrep'):
                return {'state': 'observed', 'data': b'123\n', 'returncode': 0}
            return {'state': 'unavailable', 'data': b'', 'returncode': None}
        with mock.patch.object(checker.sys, 'platform', 'darwin'), \
             mock.patch.object(checker.platform, 'machine', return_value='x86_64'), \
             mock.patch.object(checker, 'command', side_effect=commands), \
             mock.patch.object(checker, 'metal_report', return_value={'state': 'no_device_reported', 'device_count': 0}), \
             mock.patch.object(checker, 'decode_report', side_effect=OSError('private-user-name')):
            report = checker.collect()
        self.assertEqual(report['state'], 'macos-runtime-observed')
        self.assertEqual(report['windowserver']['state'], 'process_observed')
        self.assertFalse(report['windowserver']['accelerated_compositing_verified'])
        self.assertFalse(report['gpu_execution_verified'])
        self.assertFalse(report['native_target_boot_verified'])
        self.assertEqual(report['video_decode']['state'], 'query_unavailable')
        self.assertIn({'code': 'METAL_DEVICE_NOT_REPORTED', 'state': 'missing'}, report['findings'])
        self.assertNotIn('private', json.dumps(report))

    def test_simulated_query_failure_is_unverified_instead_of_missing_hardware(self):
        with mock.patch.object(checker.sys, 'platform', 'darwin'), \
             mock.patch.object(checker.platform, 'machine', return_value='arm64'), \
             mock.patch.object(checker, 'command', return_value={'state': 'unavailable', 'data': b'', 'returncode': None}), \
             mock.patch.object(checker, 'metal_report', side_effect=OSError()), \
             mock.patch.object(checker, 'decode_report', side_effect=OSError()):
            report = checker.collect()
        self.assertEqual(report['metal']['state'], 'query_unavailable')
        self.assertNotIn({'code': 'METAL_DEVICE_NOT_REPORTED', 'state': 'missing'}, report['findings'])
        self.assertEqual(report['firmware_secure_boot']['state'], 'unverified')

    def test_decode_api_support_does_not_certify_real_decode_or_encode(self):
        probe = mock.Mock(return_value=True)
        with mock.patch.object(checker.c, 'CDLL', return_value=mock.Mock(VTIsHardwareDecodeSupported=probe)):
            report = checker.decode_report()
        self.assertEqual(report['hardware_decode_reported'], {'h264': True, 'hevc': True, 'av1': True})
        self.assertEqual([call.args[0] for call in probe.call_args_list],
                         [int.from_bytes(code, 'big') for code in (b'avc1', b'hvc1', b'av01')])
        self.assertFalse(report['decode_execution_verified'])
        self.assertFalse(report['encode_execution_verified'])

    def test_app_count_is_bounded_before_reads(self):
        with mock.patch.object(checker, 'app_report') as apps:
            with self.assertRaises(checker.InputError):
                checker.collect([Path('unselected')] * 17)
        apps.assert_not_called()

    def test_report_destination_cannot_overwrite_apps_efi_or_selected_input(self):
        selected = self.root / 'selected.json'
        selected.write_text('keep original')
        for destination in (selected, self.root / 'Selected.app/Contents/resource.json',
                            self.root / 'EFI/report.json', self.root / 'diagnostics.txt'):
            with self.assertRaises(checker.InputError):
                checker.report_destination(destination, [selected])
        self.assertEqual(selected.read_text(), 'keep original')
        with mock.patch.object(checker.sys, 'platform', 'darwin'):
            with self.assertRaises(checker.InputError):
                checker.report_destination(Path('/System/report.json'), [])

    def test_non_regular_inputs_are_rejected_before_any_open(self):
        with mock.patch.object(checker.os, 'open') as opener:
            with self.assertRaisesRegex(checker.InputError, '^not_regular_file$'):
                checker.inspect_binary(self.root)
        opener.assert_not_called()
        with mock.patch.object(Path, 'stat', return_value=mock.Mock(st_mode=stat.S_IFIFO | 0o600)), \
             mock.patch.object(checker.os, 'open') as opener:
            with self.assertRaisesRegex(checker.InputError, '^not_regular_file$'):
                checker.inspect_binary(self.root / 'synthetic-fifo')
        opener.assert_not_called()
        if hasattr(os, 'mkfifo'):
            fifo = self.root / 'actual-fifo'
            os.mkfifo(fifo)
            with mock.patch.object(checker.os, 'open') as opener:
                with self.assertRaisesRegex(checker.InputError, '^not_regular_file$'):
                    checker.inspect_binary(fifo)
            opener.assert_not_called()

    def test_file_replaced_with_special_file_is_rechecked_without_reading(self):
        selected = self.executable(binary())
        descriptor = os.open(selected, os.O_RDONLY)
        with mock.patch.object(checker.os, 'open', return_value=descriptor) as opener, \
             mock.patch.object(checker.os, 'fstat', return_value=mock.Mock(st_mode=stat.S_IFIFO | 0o600)):
            with self.assertRaisesRegex(checker.InputError, '^not_regular_file$'):
                checker.open_regular(selected)
        if hasattr(os, 'O_NONBLOCK'):
            self.assertTrue(opener.call_args.args[1] & os.O_NONBLOCK)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_file_identity_swap_closes_descriptor_before_parsing(self):
        selected = self.executable(binary())
        before = selected.stat()
        descriptor = os.open(selected, os.O_RDONLY)
        changed = mock.Mock(st_mode=before.st_mode, st_dev=before.st_dev, st_ino=before.st_ino + 1)
        with mock.patch.object(checker.os, 'open', return_value=descriptor), \
             mock.patch.object(checker.os, 'fstat', return_value=changed):
            with self.assertRaisesRegex(checker.InputError, '^input_changed_before_open$'):
                checker.inspect_binary(selected)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_atomic_replace_failure_preserves_report_and_redacts_cli_error(self):
        output = self.root / 'private-user-name-report.json'
        before = b'{"keep":"original"}\n'
        output.write_bytes(before)
        errors, console = io.StringIO(), io.StringIO()
        with mock.patch.object(checker.sys, 'platform', 'win32'), \
             mock.patch.object(checker.os, 'replace', side_effect=OSError('private-user-name replace failed')), \
             redirect_stderr(errors), redirect_stdout(console):
            status = checker.main(['--out', str(output)])
        self.assertEqual(status, 3)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.compatibility-*.tmp')), [])
        self.assertNotIn('private', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())
        self.assertNotIn(str(self.root), errors.getvalue())
        self.assertEqual(console.getvalue(), '')

    def test_directory_write_failure_returns_controlled_private_cli_status(self):
        blocker = self.root / 'private-user-name'
        blocker.write_bytes(b'keep original')
        errors = io.StringIO()
        with mock.patch.object(checker.sys, 'platform', 'win32'), redirect_stderr(errors):
            status = checker.main(['--out', str(blocker / 'report.json')])
        self.assertEqual(status, 3)
        self.assertEqual(blocker.read_bytes(), b'keep original')
        self.assertNotIn('private', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())

    def test_flush_failure_preserves_report_and_removes_temporary_file(self):
        output = self.root / 'report.json'
        output.write_bytes(b'old complete report')
        with mock.patch.object(checker.os, 'fsync', side_effect=OSError('private filesystem error')):
            with self.assertRaises(OSError):
                checker.write_report(output, {'schema': 1})
        self.assertEqual(output.read_bytes(), b'old complete report')
        self.assertEqual(list(self.root.glob('.compatibility-*.tmp')), [])

    def test_successful_replace_publishes_complete_json_after_preserving_old_report(self):
        output = self.root / 'report.json'
        output.write_bytes(b'old complete report')
        expected = {'schema': 1, 'long_value': 'test' * 20000}
        replacement = os.replace
        def verify_transaction(source, destination):
            self.assertEqual(Path(destination).read_bytes(), b'old complete report')
            self.assertEqual(json.loads(Path(source).read_text()), expected)
            self.assertEqual(Path(source).parent, Path(destination).parent)
            replacement(source, destination)
        with mock.patch.object(checker.os, 'replace', side_effect=verify_transaction):
            checker.write_report(output, expected)
        self.assertEqual(json.loads(output.read_text()), expected)
        self.assertEqual(list(self.root.glob('.compatibility-*.tmp')), [])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeCompatibilityTests))
    (ROOT / 'tests/native-compatibility-test-report.json').write_text(json.dumps({
        'test_type': 'Synthetic app metadata, privacy and failure cases; Windows platform guard',
        'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'successful': result.wasSuccessful(),
        'native_macos_hardware_tests': 0, 'apps_launched': 0, 'system_policy_changes': 0,
    }, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() else 1)
