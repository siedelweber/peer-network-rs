"""Independent integer-only carrier vectors; no codec or interchange imports.

Fraction arithmetic derives the exact interval relations from the published
integer formula. The records exact-route cross-check is a separate Rust control.
These are golden carrier values, not numerical-law evidence.
"""
from fractions import Fraction
import copy
import json
from pathlib import Path


def encode(value):
    def head(kind, number):
        if number < 24:
            return bytes([32 * kind + number])
        for width, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if number < 1 << (8 * width):
                return bytes([32 * kind + extra]) + number.to_bytes(width, 'big')
        raise ValueError('unsigned overflow')
    if value is None:
        return b'\xf6'
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, str):
        data = value.encode('utf8')
        return head(3, len(data)) + data
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(encode, value))
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(encode(k) + encode(v) for k, v in value.items())
    raise ValueError('unsupported fixture kind')


def exact(bits):
    sign = -1 if bits >> 63 else 1
    exponent = (bits >> 52) & 2047
    fraction = bits & ((1 << 52) - 1)
    if exponent == 2047 or bits == 1 << 63:
        raise ValueError('not a finite canonical endpoint')
    return sign * Fraction(fraction if exponent == 0 else (1 << 52) + fraction) * Fraction(2) ** (-1074 if exponent == 0 else exponent - 1075)


def q(value):
    value = Fraction(value)
    return [str(value.numerator), str(value.denominator)]


def interval(lower, upper=None, li=True, ui=True):
    return [lower, li, lower if upper is None else upper, ui]


def membership(evaluated, target):
    lo, li, hi, ui = evaluated
    tl, tli, th, tui = target
    lo, hi, tl, th = map(exact, (lo, hi, tl, th))
    if (lo > tl or lo == tl and (not li or tli)) and (hi < th or hi == th and (not ui or tui)):
        return 0
    if hi < tl or lo > th or hi == tl and not (ui and tli) or lo == th and not (li and tui):
        return 1
    return 2


def base(evaluated, target=None):
    if target is None:
        target = evaluated
    result = membership(evaluated, target)
    return {0: 1, 1: [1, [[2, q(0)]], 0], 2: [], 3: [[], []],
            4: [target, target], 5: 0, 6: [0, None, result, 0],
            7: [[None, evaluated, result]], 8: None, 9: 0}


def vectors():
    rows = []
    def add(name, value, refusal=None, raw=None):
        endpoints = []
        for test in value[7]:
            endpoints.extend((test[1][0], test[1][2]))
        pairs = [q(exact(bits)) for bits in endpoints if bits != 1 << 63 and ((bits >> 52) & 2047) != 2047]
        def public(item):
            if isinstance(item, bytes):
                return {'source_hex': item.hex()}
            if isinstance(item, list):
                return [public(v) for v in item]
            return item
        relation_inputs = None
        if refusal is None and value[6][0] == 0 and value[7]:
            relation_inputs = [[q(exact(e[0])), e[1], q(exact(e[2])), e[3]] for e in [value[7][0][1], value[4][1]]]
        rows.append(dict(case=name, canonical=(encode(value) if raw is None else raw).hex(), refusal=refusal,
                         original_question=public([value[1], value[2], value[3], value[6]]),
                         membership_operands=relation_inputs,
                         tests=public(value[7]),
                         endpoint_patterns=[f'{b:016x}' for b in endpoints], exact_operands=pairs, expected_relation=value[6][2]))
    one = 0x3ff0000000000000
    # Intentionally unsorted: readers consume the corpus in this order.
    for bits in [256, one, 1, 65536, 24, 0x000fffffffffffff, 0x0010000000000000, 0, 0x8000000000000001]:
        value = base(interval(bits))
        add(f'endpoint-{bits:016x}', value)
        canonical = encode(value)
        short = encode(bits)
        if len(short) < 9:
            longer = b'\x1b' + bits.to_bytes(8, 'big')
            # Replace an endpoint inside an enclosure, not an unrelated integer.
            original = encode(interval(bits))
            replacement = b'\x84' + longer + b'\xf5' + short + b'\xf5'
            add(f'longer-{bits:016x}', value, 'ShortestHead', canonical.replace(original, replacement, 1))
    for name, evaluated, target in [
        ('contained', interval(one), interval(0, one)),
        ('disjoint', interval(0), interval(one)),
        ('straddle', interval(0, one + 1), interval(0, one)),
        ('open-boundary', interval(one), interval(0, one, ui=False)),
    ]:
        add(name, base(evaluated, target))
    for bits in [one + 1, one - 1, one, 1, 0x8000000000000001, 0x7fefffffffffffff, 0xffefffffffffffff]:
        for predicate in range(1, 6):
            value = base(interval(bits))
            x = exact(bits)
            relation = {1: x <= 1, 2: x < 1, 3: x == 1, 4: x >= 1, 5: x > 1}[predicate]
            value[4] = [None, None]
            value[6] = [predicate, q(1), 0 if relation else 1, 5]
            value[7][0][2] = value[6][2]
            add(f'threshold-{predicate}-{bits:016x}', value)
    value = base(interval(0x4340000000000000))
    value[1] = [1, [[0, 'original', []]], 0]
    value[2] = [['original', b'9007199254740993', [0, q(9007199254740993)]]]
    add('original-not-rounded', value)
    value = base(interval(one))
    value[1] = [1, [[1, 0]], 0]
    value[3] = [[['rung', q(0), True, q(2), True]], []]
    value[4] = [None, None]
    value[6] = [1, q(1), 0, 4]
    value[7] = [[0, interval(one, one+1), 2], [1, interval(one), 0]]
    value[8] = [0, [q(2), q(1), q(0)], [[0, 0, 2], [1, 1, 0]]]
    add('indecisive-then-pass', value)
    zero = copy.deepcopy(value)
    zero[7][1] = [1, interval(one+1), 1]
    zero[7].append([2, interval(0), 0])
    zero[8][2] = [[0, 0, 2], [1, 1, 1], [2, 2, 0]]
    add('accepted-zero', zero)
    refused = copy.deepcopy(value)
    refused[7] = refused[7][:1]
    refused[8][2] = refused[8][2][:1]
    refused[6][2] = 2
    refused[9] = 5
    add('operational-prefix', refused)
    bad = copy.deepcopy(value)
    bad[7].append([2, interval(0), 0])
    bad[8][2].append([2, 2, 0])
    add('after-pass', bad, 'Structure(TerminalPass)')
    bad = copy.deepcopy(refused)
    bad[7][0][0] = 1
    bad[8][2][0][0] = 1
    add('skipped-refusal', bad, 'Structure(RefusalPrefix)')
    bad = copy.deepcopy(refused)
    bad[9] = 0
    add('completed-no-pass', bad, 'Structure(TerminalPass)')
    good = base(interval(one))
    for name, bits, error in [('negative-zero',1<<63,'NegativeZero'), ('infinity',0x7ff0000000000000,'NonFinite'),
                              ('negative-infinity',0xfff0000000000000,'NonFinite'), ('nan',0x7ff0000000000001,'NonFinite')]:
        bad = copy.deepcopy(good)
        bad[4][0][0] = bits
        add(name,bad,f'Structure({error})')
    raw = encode(good)
    for name, changed, error in [('trailing',raw+b'\x00','Trailing'),('tag',b'\xc0'+raw,'Tag'),
                                  ('indefinite',b'\xbf'+raw[1:]+b'\xff','Indefinite'),
                                  ('float',raw[:2]+b'\xf9\x3c\x00'+raw[3:],'Float'),
                                  ('long-map',b'\xb8\x0a'+raw[1:],'ShortestHead'),
                                  ('duplicate',raw[:3]+b'\x00'+raw[4:],'DuplicateKey'),
                                  ('wrong-order',raw[:1]+b'\x01'+raw[2:],'MemberOrder'),
                                  ('unknown-key',raw[:1]+b'\x0a'+raw[2:],'UnknownKey')]:
        add(name,good,error,changed)
    bad=copy.deepcopy(good); bad[0]=2; add('unknown-edition',bad,'UnknownCode')
    bad=copy.deepcopy(good); bad[1][1][0][0]=17; add('unknown-node',bad,'UnknownCode')
    bad=copy.deepcopy(good); bad[4][0][1]=False; add('open-singleton',bad,'Structure(Enclosure)')
    bad=copy.deepcopy(good); bad[1]=[1,[[2,q(0)],[2,q(0)],[4,0,1]],2]; add('duplicate-node',bad,'Structure(CanonicalNodes)')
    bad=copy.deepcopy(good); bad[1]=[1,[[2,q(0)],[2,q(1)],[4,1,0]],2]; add('node-order',bad,'Structure(CanonicalNodes)')
    bad=copy.deepcopy(good); bad[1]=[1,[[3,0]],0]; add('forward-node',bad,'Structure(Reference)')
    bad=copy.deepcopy(good); bad[1][1][0][1]=['2','2']; add('unreduced-rational',bad,'Structure(Rational)')
    bad=copy.deepcopy(good); bad[2]=[['9name',b'x',[7]]]; add('invalid-name',bad,'Structure(Name)')
    bad=copy.deepcopy(good); bad[3][0]=[['box',q(1),True,q(0),True]]; add('reversed-domain',bad,'Structure(Domain)')
    bad=copy.deepcopy(good); bad[5]=1; add('false-adjustment',bad,'Structure(Adjustment)')
    bad=copy.deepcopy(good); bad[4]=[None,None]; add('missing-membership-enclosures',bad,'Structure(Predicate)')
    bad=copy.deepcopy(good); bad[7][0][2]=1; add('false-test-polarity',bad,'Structure(Polarity)')
    bad=copy.deepcopy(good); bad[7][0][0]=0; add('non-rung-subject',bad,'Structure(Tests)')
    bad=copy.deepcopy(good); bad[6][3]=5; add('fixed-membership',bad,'Structure(Consumer)')
    bad=copy.deepcopy(value); bad[8]=None; add('missing-rung-grid',bad,'Structure(RungPrefix)')
    bad=copy.deepcopy(good); bad[1][1][0]=[3,0,0]; add('wrong-node-arity',bad,'Arity')
    bad=copy.deepcopy(good); bad[0]='1'; add('wrong-item-kind',bad,'ItemKind')
    bad=copy.deepcopy(good); bad[2]=[['x',b'bytes',[3,'text']]]
    invalid=encode(bad).replace(b'\x64text',b'\x64\xffext',1); add('invalid-utf8',bad,'Utf8',invalid)
    add('truncated',good,'Truncated',encode(good)[:-1])
    for code in range(3,17):
        v=copy.deepcopy(good)
        if code in (4,5,6,7,15):
            nodes=[[2,q(0)],[2,q(1)],[code,0,1]]
        elif code==13:
            nodes=[[2,q(1)],[13,0,q('1/2')]]
        elif code in (14,16):
            nodes=[[2,q(0)],[code,0,0]]
            v[3][0]=[['box',q(0),True,q(1),True]]
        else:
            nodes=[[2,q(1)],[code,0]]
        v[1]=[1,nodes,len(nodes)-1]
        add(f'quantity-constructor-{code}',v)
    v=copy.deepcopy(good)
    v[1]=[1,[[0,'input',[[1,'array'],[0,0]]]],0]
    v[2]=[['input',b'public-source',[5,[['array',[4,[[1,one],[0,q(1)],[2,b'bytes'],[3,'text-\u03bb'],[6,True],[7]]]]]]]]
    add('complete-data-vocabulary',v)
    v=copy.deepcopy(good); v[1]=[1,[[2,q(0)],[2,q(1)],[4,0,1]],2]; v[3][1]=[[1,0,1]]
    add('hypothesis-postorder',v)
    return dict(provenance='Independent RFC 8949 integer encoder and exact Fraction cross-products; records exact-route rational cross-check; no native-law evidence.',
                distinct_inputs=len({row['canonical'] for row in rows}), cases=rows)


def check(path):
    expected = vectors()
    if json.loads(Path(path).read_text()) != expected:
        raise ValueError('binary64 corpus differs from independent integer derivation')
    return expected


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    path = Path('packages/host/tests/data/binary64-carriers.json')
    if args.write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vectors(), indent=2) + '\n')
    result = check(path)
    print(f"BINARY64-VECTORS cases={len(result['cases'])} distinct={result['distinct_inputs']} order=unsorted")
