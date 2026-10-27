"""Public CLI regressions for the restricted evaluator and mutation checker."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RULE = """logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\tool.exe'
  condition: selection
"""


class EvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tests').mkdir()
        self.rule = RULE
        self.event = dict(synthetic=True, event_id='test-001', product='windows',
                          category='process_creation', EventID=1,
                          timestamp_utc='2026-10-27T00:00:00Z', host='TEST',
                          Image=r'C:\TOOLS\TOOL.EXE', CommandLine='tool.exe /CREATE /TR',
                          User='TEST\\analyst')
        self.manifest = dict(rule=str(self.root / 'rule.yml'), cases=[dict(
            fixture=str(self.root / 'event.jsonl'), event_id='test-001', expected_match=True)])

    def invoke(self, script='evaluate.py', fixture=None):
        (self.root / 'rule.yml').write_text(self.rule)
        (self.root / 'event.jsonl').write_text(
            json.dumps(self.event) + '\n' if fixture is None else fixture)
        manifest = self.root / 'tests' / 'manifest.json'
        manifest.write_text(json.dumps(self.manifest))
        return subprocess.run([sys.executable, str(ROOT / 'scripts' / script),
                               str(manifest)], capture_output=True, text=True)

    def assert_error(self, message, **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_duplicate_keys_real_loading_paths(self):
        for duplicate in ["    Image|endswith: '\\other.exe'\n",
                          '  condition: selection\n']:
            self.rule = RULE.replace('  condition: selection\n', duplicate + '  condition: selection\n')
            for script in ('evaluate.py', 'mutation_check.py'):
                with self.subTest(duplicate=duplicate, script=script):
                    self.assert_error('Duplicate YAML key', script=script)

    def test_unsupported_modifiers(self):
        for modifier in ('startswith', 're', 'endswith|all', 'contains|nocase'):
            with self.subTest(modifier=modifier):
                self.rule = RULE.replace('Image|endswith', 'Image|' + modifier)
                self.assert_error('Unsupported field/modifier')

    def test_wildcard_literals(self):
        for literal in ('*tool.exe', '?ool.exe'):
            with self.subTest(literal=literal):
                self.rule = RULE.replace('\\tool.exe', literal)
                self.assert_error('without wildcards')

    def test_empty_manifest(self):
        self.manifest['cases'] = []
        self.assert_error('Empty test manifest')

    def test_empty_fixture(self):
        self.assert_error('exactly one JSONL record', fixture='')

    def test_missing_routing_fields(self):
        for field in ('product', 'category', 'EventID'):
            with self.subTest(field=field):
                value = self.event.pop(field)
                self.assert_error('Missing routing field: ' + field)
                self.event[field] = value

    def test_event_id_requires_integer(self):
        for value in ('1', 1.0, True, None):
            with self.subTest(value=value):
                self.event['EventID'] = value
                self.assert_error('EventID must be an integer')

    def test_missing_detection_field_nonmatch(self):
        del self.event['Image']
        self.manifest['cases'][0]['expected_match'] = False
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('actual=False', result.stdout)

    def test_case_insensitive_operations(self):
        for selection, expected in [
            ("Image|endswith: '\\tool.exe'", True),
            ("CommandLine|contains: ['/missing', '/create']", True),
            ("CommandLine|contains|all: ['/create', '/tr']", True),
            ("CommandLine|contains|all: ['/create', '/missing']", False),
        ]:
            with self.subTest(selection=selection):
                self.rule = RULE.replace("Image|endswith: '\\tool.exe'", selection)
                self.manifest['cases'][0]['expected_match'] = expected
                result = self.invoke()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'actual={expected}', result.stdout)

    def test_expectation_mismatch_exit(self):
        self.manifest['cases'][0]['expected_match'] = False
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn('FAIL test-001', result.stdout)

    def test_mutations_require_passing_original(self):
        self.manifest['cases'][0]['expected_match'] = False
        result = self.invoke('mutation_check.py')
        self.assertEqual(result.returncode, 1)
        self.assertIn('original rule must pass', result.stdout)
        self.assertNotIn('mutations detected', result.stdout)

    def test_invalid_mutation_is_not_detected(self):
        # Inject an evaluation error to verify it cannot satisfy the mutation gate.
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch
        sys.path.insert(0, str(ROOT / 'scripts'))
        self.addCleanup(sys.path.remove, str(ROOT / 'scripts'))
        import mutation_check
        self.rule = RULE.replace('  condition:', "    ParentImage|endswith: '\\parent.exe'\n  condition:")
        self.event['ParentImage'] = r'C:\parent.exe'
        self.assertEqual(self.invoke().returncode, 0)
        output = io.StringIO()
        with patch.object(sys, 'argv', ['mutation_check.py', str(self.root / 'tests/manifest.json')]), \
                patch.object(mutation_check, 'check', side_effect=[(0, ''), ValueError('invalid'), (1, '')]), \
                redirect_stdout(output):
            self.assertEqual(mutation_check.main(), 2)
        self.assertIn('1/2 predicate mutations detected', output.getvalue())
        self.assertIn('ERROR: invalid predicate mutation', output.getvalue())


if __name__ == '__main__':
    unittest.main()
