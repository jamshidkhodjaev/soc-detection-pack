"""Strictly validate a rule snapshot and atomically publish generated Splunk SPL."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

from evaluate import load_rule


def convert(source, output):
    source, output = Path(source), Path(output)
    # Snapshot once: validation and conversion must consume identical bytes.
    content = source.read_bytes()
    with tempfile.TemporaryDirectory(prefix='.sigma-', dir=output.parent) as work:
        snapshot = Path(work) / 'rule.yml'
        snapshot.write_bytes(content)
        load_rule(snapshot)
        temporary_output = Path(work) / 'query.spl'
        result = subprocess.run([
            sys.executable, '-m', 'sigma.cli.main', 'convert',
            '-t', 'splunk', '-p', 'sysmon', '-f', 'default',
            '-o', str(temporary_output), str(snapshot),
        ])
        if result.returncode != 0:
            return result.returncode
        if not temporary_output.is_file() or temporary_output.stat().st_size == 0:
            raise ValueError('Converter produced no nonempty output')
        # Same filesystem as destination; failed conversion never touches it.
        temporary_output.replace(output)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rule', type=Path)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return convert(args.rule, args.output)
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
