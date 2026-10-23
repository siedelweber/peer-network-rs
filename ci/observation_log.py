"""Separate complete observation records from the gate's diagnostic log."""
import json
from pathlib import Path
import sys

KINDS = {'trace', 'span_envelope', 'metering', 'metric_summary', 'export_summary', 'observation_artifact', 'observation_status'}


def separate(source, observations, diagnostics):
    count = 0
    for line in source:
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            value = None
        if isinstance(value, dict) and value.get('kind') in KINDS:
            observations.write(line)
            count += 1
        else:
            diagnostics.write(line)
    return count


def main():
    source, artifact = map(Path, sys.argv[1:])
    with source.open('rb') as incoming, artifact.open('wb') as outgoing:
        count = separate(incoming, outgoing, sys.stdout.buffer)
    print(f'OBSERVATION-STREAM records={count} bytes={artifact.stat().st_size} artifact={artifact}')


if __name__ == '__main__':
    main()
