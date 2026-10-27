"""Conversion gate and output preservation, including the real locked converter."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import convert_rule


class ConversionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'input rule.yml'
        self.source.write_bytes((ROOT / 'rules/schtasks_creation_suspicious_path.yml').read_bytes())
        self.output = self.root / 'output query.spl'
        self.output.write_text('previous output\n')

    def invoke(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            result = convert_rule.main([str(self.source), '-o', str(self.output)])
        return result, errors.getvalue()

    def test_duplicates_rejected_before_conversion(self):
        text = self.source.read_text()
        self.source.write_text(text.replace(
            "        Image|endswith: '\\schtasks.exe'",
            "        Image|endswith: '\\other.exe'\n        Image|endswith: '\\schtasks.exe'"))
        for existing in (True, False):
            with self.subTest(existing=existing):
                if not existing:
                    self.output.unlink()
                with patch.object(convert_rule.subprocess, 'run') as converter:
                    result, error = self.invoke()
                self.assertNotEqual(result, 0)
                self.assertIn('Duplicate YAML key', error)
                converter.assert_not_called()
                if existing:
                    self.assertEqual(self.output.read_text(), 'previous output\n')
                else:
                    self.assertFalse(self.output.exists())

    def test_converter_failure_preserves_output(self):
        def failing_converter(command):
            Path(command[command.index('-o') + 1]).write_text('partial output')
            return subprocess.CompletedProcess(command, 7)
        with patch.object(convert_rule.subprocess, 'run', side_effect=failing_converter):
            result, _ = self.invoke()
        self.assertEqual(result, 7)
        self.assertEqual(self.output.read_text(), 'previous output\n')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         ['input rule.yml', 'output query.spl'])

    def test_valid_input_real_conversion(self):
        result = subprocess.run([
            sys.executable, str(ROOT / 'scripts/convert_rule.py'),
            str(self.source), '-o', str(self.output),
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_bytes(),
                         (ROOT / 'converted/schtasks_creation_suspicious_path.spl').read_bytes())

    def test_conversion_consumes_validated_snapshot(self):
        original = self.source.read_bytes()
        real_run = subprocess.run
        def change_source_then_convert(command):
            # Simulate a source edit after validation, before converter execution.
            self.source.write_text('invalid: [')
            self.assertEqual(Path(command[-1]).read_bytes(), original)
            return real_run(command, capture_output=True, text=True)
        with patch.object(convert_rule.subprocess, 'run', side_effect=change_source_then_convert):
            result, error = self.invoke()
        self.assertEqual(result, 0, error)
        self.assertEqual(self.output.read_bytes(),
                         (ROOT / 'converted/schtasks_creation_suspicious_path.spl').read_bytes())


if __name__ == '__main__':
    unittest.main()
