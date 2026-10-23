"""Stable doctest identities: lexical file path, item and source-order ordinal."""

from collections import defaultdict
import posixpath
import re

from devperf import StructuralError


def identities(names):
    groups = defaultdict(list)
    seen = set()
    for name in names:
        match = re.fullmatch(r'(.+?) -\s*(.*?)\s*\(line ([0-9]+)\)', name)
        if match is None:
            raise StructuralError('malformed doctest identity: ' + name)
        path, item, line = match.groups()
        base = posixpath.normpath(path) + ' - ' + (item or '<module>')
        position = (base, int(line))
        if position in seen:
            raise StructuralError('ambiguous doctest source position: ' + name)
        seen.add(position)
        groups[base].append((int(line), name))
    result = {}
    for base, entries in groups.items():
        for ordinal, (_, name) in enumerate(sorted(entries), 1):
            result[name] = f'doctest::{base} [example {ordinal}]'
    if len(set(result.values())) != len(result):
        raise StructuralError('duplicate normalized doctest identity')
    return result
