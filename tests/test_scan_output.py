import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'storage-analyzer/scripts'))
import scan


class ScanOutputTests(unittest.TestCase):
    def test_output_modes_preserve_all_platforms_and_warnings(self):
        for platform, scanner in [('win32', 'scan_windows'),
                                  ('darwin', 'scan_macos'),
                                  ('linux', 'scan_linux')]:
            for mode in ['stdout', 'file', 'directory']:
                with self.subTest(platform=platform, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / '扫描.json'
                    args = {'stdout': [], 'file': ['--output', str(target)],
                            'directory': ['--output-dir', str(root / 'reports')]}[mode]
                    buffer = io.BytesIO()
                    output = io.TextIOWrapper(buffer, encoding='utf-8')

                    def fake_scan():
                        scan.SCAN_ERRORS.add('模拟未读目录')
                        return {'os': platform}, {'files': [{'name': '中文路径'}]}

                    scan.SCAN_ERRORS.add('stale warning')
                    with patch.object(sys, 'argv', ['scan.py', *args]), \
                         patch.object(sys, 'platform', platform), \
                         patch.object(sys, 'stdout', output), \
                         patch.object(scan, scanner, side_effect=fake_scan):
                        scan.main()
                        output.flush()
                        printed = buffer.getvalue().decode('utf-8').strip()
                    if mode == 'stdout':
                        data = json.loads(printed)
                        self.assertEqual(list(root.iterdir()), [])
                    else:
                        written = Path(printed)
                        if mode == 'file':
                            self.assertEqual(written, target)
                        else:
                            self.assertEqual(written.parent, root / 'reports')
                            self.assertRegex(written.name, r'^scan_\d{8}_\d{6}\.json$')
                        data = json.loads(written.read_text(encoding='utf-8'))
                    self.assertEqual(data['system']['os'], platform)
                    self.assertEqual(data['groups']['files'][0]['name'], '中文路径')
                    self.assertEqual(data['warnings'], ['模拟未读目录'])
                    output.close()
