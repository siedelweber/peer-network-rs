"""Independent RFC 8949 envelope bytes, without Rust or production helpers.

Inputs are public text-carriage tests, not artifacts at assigned coordinates.
The hash audit regenerates this entire corpus; it introduces no digest.
"""
import json
from pathlib import Path


def head(major, n):
    if n < 24:
        return bytes([major * 32 + n])
    size = next(size for size in (1, 2, 4, 8) if n < 1 << (size * 8))
    return bytes([major * 32 + {1: 24, 2: 25, 4: 26, 8: 27}[size]]) + n.to_bytes(size, 'big')


def value(v):
    if isinstance(v, str):
        raw = v.encode('utf-8')
        return head(3, len(raw)) + raw
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(value(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(value(k) + value(v[k]) for k in sorted(v))
    raise ValueError(v)


def vectors(root):
    source = (root / 'packages/interchange/schema/control.graphql').read_bytes().decode('utf-8')
    role = 'org.peer-network.test.api-control-schema'
    rows = []

    def add(name, fields, expected, text=None):
        rows.append(dict(name=name, bytes=value(fields).hex(), expected=expected, source=text))

    texts = [source, '', '"\\\t\x00é e\u0301 Ω 😀', 'a\nb', 'a\rb', 'a\r\nb', 'a\nb\n', 'a\rb\r', 'a\r\nb\r\n']
    for index, text in enumerate(texts):
        add('text-' + str(index), {0: role, 1: [1, 0, 0], 2: text}, 'accepted', text)
    add('patch', {0: role, 1: [1, 0, 18446744073709551615], 2: ''}, 'accepted', '')
    for other in ['api-control-register', 'api-node-schema', 'api-node-register']:
        add(other, {0: 'org.peer-network.test.' + other, 1: [1, 0, 0], 2: ''}, 'role')
    for name, edition in [('major', [2, 0, 0]), ('minor', [1, 1, 0])]:
        add(name, {0: role, 1: edition, 2: ''}, 'edition')
    add('extra', {0: role, 1: [1, 0, 0], 2: '', 3: ''}, 'content')
    add('missing', {0: role, 1: [1, 0, 0]}, 'content')
    add('wrong-key', {0: role, 1: [1, 0, 0], 3: ''}, 'content')
    add('wrong-type', {0: role, 1: [1, 0, 0], 2: 0}, 'content')
    for name, fields in [('no-role', {1: [1, 0, 0], 2: ''}), ('no-edition', {0: role, 2: ''}), ('role-type', {0: 0, 1: [1, 0, 0], 2: ''}), ('role-label', {0: 'invalid', 1: [1, 0, 0], 2: ''}), ('version-short', {0: role, 1: [1, 0], 2: ''}), ('version-type', {0: role, 1: [1, 0, '0'], 2: ''})]:
        add(name, fields, {'no-role': 'missing-role', 'no-edition': 'missing-edition', 'role-type': 'label-type', 'role-label': 'label', 'version-short': 'version', 'version-type': 'version'}[name])
    good = value({0: role, 1: [1, 0, 0], 2: ''})
    for name, raw in [('trailing', good + b'\x00'), ('truncated', good[:-1]), ('nonpreferred', b'\xb8\x03' + good[1:]), ('invalid-utf8', good[:-1] + b'\x61\xff')]:
        rows.append(dict(name=name, bytes=raw.hex(), expected={'invalid-utf8': 'utf8'}.get(name, name), source=None))
    prefix = value(0) + value(role) + value(1) + value([1, 0, 0])
    for name, raw, expected in [
        ('duplicate-key', head(5, 4) + prefix + value(2) + value('') + value(2) + value(''), 'duplicate-key'),
        ('unsorted-keys', head(5, 3) + value(0) + value(role) + value(2) + value('') + value(1) + value([1, 0, 0]), 'unsorted-keys'),
        ('indefinite-length', b'\xbf' + good[1:] + b'\xff', 'indefinite-length'),
        ('not-a-map', value([]), 'not-a-map'),
        ('tagged-content', good[:-1] + head(6, 0) + value(''), 'content'),
        ('non-integer-key', head(5, 4) + good[1:] + value('x') + value(''), 'non-integer-key'),
        ('unpaired-high-surrogate', good[:-1] + head(3, 3) + b'\xed\xa0\x80', 'utf8'),
        ('unpaired-low-surrogate', good[:-1] + head(3, 3) + b'\xed\xb0\x80', 'utf8'),
    ]:
        rows.append(dict(name=name, bytes=raw.hex(), expected=expected, source=None))
    assert len({row['bytes'] for row in rows}) == len(rows)
    return rows


def encoded(root):
    return (json.dumps(vectors(root), ensure_ascii=True, indent=2) + '\n').encode()


if __name__ == '__main__':
    import sys
    root = Path(sys.argv[1])
    target = root / 'packages/interchange/tests/corpus/control-schema.json'
    if sys.argv[2] == 'write':
        target.write_bytes(encoded(root))
    elif target.read_bytes() != encoded(root):
        raise SystemExit('independent control schema corpus differs')
