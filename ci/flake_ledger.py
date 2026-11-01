"""Retain failed required attempts and observable slow successes across gate runs."""

import fcntl
import json
import os
from pathlib import Path
import time
import uuid


def append(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(row, sort_keys=True)+'\n')
        stream.flush()
    print('FLAKE-LEDGER '+json.dumps(row, sort_keys=True), flush=True)


class Session:
    """A retry is a new required execution after a failure, never an automatic replay."""
    def __init__(self, source, path=None):
        self.path = Path(path) if path is not None else Path(os.environ.get('PN_FLAKE_LEDGER', str(Path(os.environ.get('CARGO_TARGET_DIR', '.lane'))/'gate-flakes.jsonl')))
        self.source = source
        self.run = os.environ.get('PN_BUILDGRAPH_RUN', 'standalone')
        self.previous = {}
        self.failures = set()
        self.retried = set()
        if self.path.exists():
            with self.path.open() as stream:
                fcntl.flock(stream, fcntl.LOCK_SH)
                for line in stream:
                    row = json.loads(line)
                    if row['event'] in {'failure', 'retry-result'}:
                        self.previous[row['case']] = row
                    if row['event'] == 'failure': self.failures.add(row['case'])

    def record(self, event, case, error, **fields):
        row = dict(schema=1, event=event, commit=self.source, case=case, error=error,
                   run=self.run, utc_seconds=time.time(), node_load=list(os.getloadavg()), **fields)
        append(self.path, row)
        return row

    def begin(self, case):
        previous = self.previous.get(case)
        if previous and previous.get('outcome') == 'failed':
            self.retried.add(case)
            return self.record('retry', case, previous['error'], previous_commit=previous['commit'],
                               previous_run=previous['run'], finding='recurrence', attempt=uuid.uuid4().hex)
        return None

    def finish(self, case, outcome, error=''):
        if outcome == 'failed':
            return self.record('failure', case, error or 'required case failed without a diagnostic',
                               outcome=outcome, finding='recurrence' if case in self.failures else 'required-case-failure')
        if case in self.retried:
            return self.record('retry-result', case, self.previous[case]['error'], outcome=outcome,
                               previous_commit=self.previous[case]['commit'], finding='recurrence')
        return None
