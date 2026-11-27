"""Independent unsigned common-document vectors using only Python's standard library."""

import hashlib
import json
import sys
from pathlib import Path


def word(number):
    return bytes([number]) * 32


def head(major, number):
    if number < 24:
        return bytes([32 * major + number])
    for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if number < 1 << (8 * width):
            return bytes([32 * major + marker]) + number.to_bytes(width, 'big')
    raise ValueError('unsigned word out of range')


def encode(value):
    if isinstance(value, int):
        if value < 0:
            raise ValueError('unsigned fixtures only')
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode('utf-8')
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(encode(item) for item in value)
    if isinstance(value, dict):
        pairs = sorted((encode(key), encode(item)) for key, item in value.items())
        return head(5, len(pairs)) + b''.join(key + item for key, item in pairs)
    raise ValueError('unknown fixture value')


NAMESPACES = {
    'act': 'org.peer-network.test.act',
    'witness': 'org.peer-network.test.act.witness',
}
RECIPES = {
    'act': 'pn-act-authentication/common-act/v1',
    'witness': 'pn-act-authentication/witnessed-act/v1',
}


def document(role, members, *, namespace=None, major=1, minor=0, patch=0, extra=None):
    value = {0: NAMESPACES[role] if namespace is None else namespace,
             1: [major, minor, patch], 2: members}
    if extra is not None:
        value[3] = extra
    return encode(value)


def case(label, role, members):
    canonical = document(role, members)
    return dict(label=label, role=role, members=[member.hex() for member in members],
                canonical=canonical.hex(), length=len(canonical),
                recipe=RECIPES[role], name=hashlib.sha256(canonical).hexdigest())


def refusals(role, members):
    rows = []

    def add(label, payload, expected):
        rows.append(dict(label=label, role=role, canonical=payload.hex(), expected=expected))

    add('count', document(role, members[:-1]), 'Count')
    shortened = [members[0][:-1], *members[1:]]
    add('member-width', document(role, shortened), 'MemberWidth')
    add('member-type', document(role, [0, *members[1:]]), 'MemberType')
    add('nonpreferred-map-head', bytes((184, 3)) + document(role, members)[1:], 'Canonical')
    add('count-before-width', document(role, shortened[:-1]), 'Count')
    add('canonical-before-count', bytes((184, 3)) + document(role, members[:-1])[1:], 'Canonical')
    add('width-before-patch', document(role, shortened, patch=1), 'MemberWidth')
    add('patch', document(role, members, patch=1), 'OperationPatch')
    add('minor', document(role, members, minor=1), 'OperationVersion')
    add('version-before-body', document(role, members, minor=1, extra=0), 'OperationVersion')
    add('extra-content', document(role, members, extra=0), 'Body')
    neighbour = NAMESPACES['witness' if role == 'act' else 'act']
    add('namespace-before-body', document(role, members, namespace=neighbour, extra=0), 'Namespace')
    add('trailing-byte', document(role, members) + bytes((0,)), 'Canonical')
    return rows


def vectors():
    act_a_members = [word(number) for number in range(1, 8)]
    act_b_members = [*act_a_members[:-1], word(8)]
    act_a = case('act-a', 'act', act_a_members)
    act_b = case('act-b', 'act', act_b_members)
    witness_a_members = [bytes.fromhex(act_a['name']), word(9), word(10), word(11)]
    witness_b_members = [bytes.fromhex(act_b['name']), word(9), word(10), word(11)]
    witness_a = case('witness-a', 'witness', witness_a_members)
    witness_b = case('witness-b', 'witness', witness_b_members)
    return dict(
        source='Independent Python standard-library CBOR encoder and SHA-256; public fixed words are unsigned fixture values, not valid approvals.',
        cases=[act_a, act_b, witness_a, witness_b],
        refusals=refusals('act', act_a_members) + refusals('witness', witness_a_members),
    )


def output():
    return (json.dumps(vectors(), indent=2, ensure_ascii=False) + '\n').encode('utf-8')


if __name__ == '__main__':
    if sys.argv[1:] == ['--write']:
        Path(__file__).with_name('common-documents.json').write_bytes(output())
    elif not sys.argv[1:]:
        sys.stdout.buffer.write(output())
    else:
        raise SystemExit('usage: common_vectors.py [--write]')
