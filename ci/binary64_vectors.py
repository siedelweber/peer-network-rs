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


def threshold_result(predicate, evaluated, threshold):
    lower, li, upper, ui = evaluated
    lower, upper = exact(lower), exact(upper)
    # The set of possible comparisons to the exact threshold determines the
    # verdict; no binary floating operation or carrier implementation is used.
    signs = set()
    if lower < threshold:
        signs.add(-1)
    if upper > threshold:
        signs.add(1)
    if lower <= threshold <= upper and (lower != threshold or li) and (upper != threshold or ui):
        signs.add(0)
    admitted = {1: {-1, 0}, 2: {-1}, 3: {0}, 4: {0, 1}, 5: {1}}[predicate]
    return 0 if signs <= admitted else 1 if signs.isdisjoint(admitted) else 2


def vectors():
    rows = []
    def add(name, value, refusal=None, raw=None):
        def shape(item, depth):
            children = [shape(v, depth+1) for v in item] if isinstance(item, list) else []
            return 1 + sum(c[0] for c in children), max([depth] + [c[1] for c in children])
        shapes = [shape(v, 1) for v in value.values()]
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
                         tests=public(value[7]), consumer=value[6][3], outcome=value[9],
                         relations=[h[0] for h in value[3][1]],
                         reader_items=1+len(value)+sum(s[0] for s in shapes), reader_depth=max(s[1] for s in shapes),
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
    # Non-dyadic thresholds cannot be touched by binary64 endpoints. Exact
    # touches use a dyadic threshold; thirds exercise rational denominators.
    two = 0x4000000000000000
    half = 0x3fe0000000000000
    quarter = 0x3fd0000000000000
    for threshold in (Fraction(1, 3), Fraction(1)):
        bounds = [(0, quarter), (quarter, half), (half, two)] if threshold != 1 else [(0, half), (0, one), (half, two), (one, two), (one+1, two)]
        for predicate in range(1, 6):
            for number, (lower, upper) in enumerate(bounds):
                for li in (False, True):
                    for ui in (False, True):
                        evaluated = interval(lower, upper, li, ui)
                        v = base(evaluated)
                        result = threshold_result(predicate, evaluated, threshold)
                        v[4] = [None, None]
                        v[6] = [predicate, q(threshold), result, 5]
                        v[7][0][2] = result
                        add(f'comparison-{predicate}-{threshold}-{number}-{int(li)}{int(ui)}', v)
    for side in ('lower', 'upper', 'left-touch', 'right-touch'):
        for a in (False, True):
            for b in (False, True):
                evaluated, target = {
                    'lower': (interval(0, one, li=a), interval(0, two, li=b)),
                    'upper': (interval(one, two, ui=a), interval(0, two, ui=b)),
                    'left-touch': (interval(0, one, ui=a), interval(one, two, li=b)),
                    'right-touch': (interval(one, two, li=a), interval(0, one, ui=b)),
                }[side]
                add(f'membership-{side}-{int(a)}{int(b)}', base(evaluated, target))
    v = base(interval(one), interval(0, two))
    v[4][0] = interval(0, one)
    v[5] = 1
    add('adjusted-free', v)
    v = copy.deepcopy(v); v[5] = 0
    add('adjusted-free-refusal', v, 'Structure(Adjustment)')

    def changed(name, edit, error, source=good):
        v = copy.deepcopy(source)
        edit(v)
        add(name, v, error)

    changed('reversed-enclosure', lambda v: v[7][0].__setitem__(1, interval(two, one)), 'Structure(Enclosure)', base(interval(one), interval(0, two)))
    changed('dangling-input', lambda v: v.__setitem__(1, [1, [[0, 'absent', []]], 0]), 'Structure(Reference)')
    data = copy.deepcopy(good)
    data[2] = [['input', b'input', [4, [[3, 'not-numeric'], [0, q(1)]]]]]
    data[1] = [1, [[0, 'input', [[0, 1]]]], 0]
    add('array-second-element', data)
    changed('dangling-path-index', lambda v: v[1][1][0].__setitem__(2, [[0, 2]]), 'Structure(Reference)', data)
    changed('dangling-path-kind', lambda v: v[1][1][0].__setitem__(2, [[1, 'absent']]), 'Structure(Reference)', data)
    changed('nonnumeric-leaf', lambda v: v[1][1][0].__setitem__(2, []), 'Structure(Reference)', data)
    changed('dangling-coordinate', lambda v: v.__setitem__(1, [1, [[1, 0]], 0]), 'Structure(Reference)')
    changed('hypothesis-operand-range', lambda v: v[3].__setitem__(1, [[0, 0, 1]]), 'Structure(Reference)')
    changed('root-not-last', lambda v: v.__setitem__(1, [1, [[2, q(0)], [2, q(1)]], 0]), 'Structure(CanonicalNodes)')
    v = copy.deepcopy(good)
    v[1] = [1, [[2, q(0)], [3, 0]], 0]
    v[3][1] = [[0, 1, 1]]
    add('root-under-hypothesis', v, 'Structure(CanonicalNodes)')
    v = copy.deepcopy(good)
    v[1] = [1, [[2, q(0)], [2, q(1)], [3, 1]], 2]
    v[3][1] = [[0, 2, 0]]
    add('direct-root-omitted', v)
    v = copy.deepcopy(good)
    v[1] = [1, [[2, q(0)], [2, q(1)], [4, 1, 0]], 2]
    v[3][1] = [[0, 0, 1]]
    add('hypothesis-before-root', v)
    v[3][1] = [[0, 1, 0]]
    add('hypothesis-wrong-order', v, 'Structure(CanonicalNodes)')
    for name, entries in [('descending', ['z', 'a']), ('duplicate', ['a', 'a'])]:
        changed('input-names-'+name, lambda v: v.__setitem__(2, [[n, b'x', [0, q(0)]] for n in entries]), 'Structure(Name)')
        changed('record-names-'+name, lambda v: v.__setitem__(2, [['input', b'x', [5, [[n, [0, q(0)]] for n in entries]]]]), 'Structure(Name)')
    changed('record-name-invalid', lambda v: v.__setitem__(2, [['input', b'x', [5, [['9bad', [0, q(0)]]]]]]), 'Structure(Name)')
    changed('domain-open-singleton', lambda v: v[3].__setitem__(0, [['box', q(0), False, q(0), True]]), 'Structure(Domain)')
    # Sorted inputs and records: first, middle, last and absent lookups.
    for name in ('a', 'm', 'z', 'missing'):
        v = copy.deepcopy(good)
        v[2] = [[n, b'x', [0, q(i)]] for i, n in enumerate(('a', 'm', 'z'))]
        v[1] = [1, [[0, name, []]], 0]
        add('input-lookup-'+name, v, 'Structure(Reference)' if name == 'missing' else None)
        v[2] = [['input', b'x', [5, [[n, [0, q(i)]] for i, n in enumerate(('a', 'm', 'z'))]]]]
        v[1] = [1, [[0, 'input', [[1, name]]]], 0]
        add('field-lookup-'+name, v, 'Structure(Reference)' if name == 'missing' else None)
    for code in (1, 2, 3, 6):
        changed(f'consumer-code-{code}', lambda v: v[6].__setitem__(3, code), None)
    for code in range(1, 7):
        v = copy.deepcopy(good); v[7] = []; v[6][2] = 2; v[9] = code
        add(f'operational-outcome-{code}', v)
    for code in (0, 2):
        v = copy.deepcopy(good); v[3][1] = [[code, 0, 0]]
        add(f'relation-code-{code}', v)
    changed('consumer-requires-proposition', lambda v: v[6].__setitem__(3, 1), 'Structure(Consumer)', base(interval(0), interval(one)))
    v = copy.deepcopy(good); v[4] = [None, None]; v[6] = [1, q(1), 0, 1]
    add('consumer-requires-membership', v, 'Structure(Consumer)')
    v = copy.deepcopy(good); v[9] = 1; v[7] = []
    add('operational-polarity', v, 'Structure(Polarity)')
    changed('completed-polarity-agreement', lambda v: v[6].__setitem__(2, 1), 'Structure(Tests)')
    changed('completed-without-test', lambda v: v.__setitem__(7, []), 'Structure(Tests)')
    v = base(interval(0, two), interval(one)); v[9] = 1
    add('operational-with-test', v, 'Structure(Tests)')
    changed('question-edition', lambda v: v[1].__setitem__(0, 2), 'UnknownCode')
    changed('one-null-enclosure', lambda v: v[4].__setitem__(0, None), 'ItemKind')
    changed('unknown-adjusted', lambda v: v.__setitem__(5, 2), 'UnknownCode')
    changed('membership-with-threshold', lambda v: v[6].__setitem__(1, q(1)), 'UnknownCode')
    for name, slot in [('consumer', 3), ('polarity', 2), ('predicate', 0)]:
        changed('unknown-'+name, lambda v: v[6].__setitem__(slot, 99), 'UnknownCode')
    changed('unknown-outcome', lambda v: v.__setitem__(9, 99), 'UnknownCode')
    changed('unknown-relation', lambda v: v[3].__setitem__(1, [[99, 0, 0]]), 'UnknownCode')
    changed('unknown-data', lambda v: v.__setitem__(2, [['input', b'x', [99, None]]]), 'UnknownCode')
    changed('unknown-path', lambda v: v[1][1][0].__setitem__(2, [[99, 0]]), 'UnknownCode', data)
    for name, fragment, error in [
        ('map-arity', b'\xa9'+raw[1:], 'Arity'),
        ('key-kind', raw[:1]+b'\x60'+raw[2:], 'ItemKind'),
        ('float32', raw[:2]+b'\xfa\x3f\x80\x00\x00'+raw[3:], 'Float'),
        ('float64', raw[:2]+b'\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00'+raw[3:], 'Float'),
        ('shortest-two', raw[:2]+b'\x19\x00\x01'+raw[3:], 'ShortestHead'),
        ('shortest-four', raw[:2]+b'\x1a\x00\x00\x00\x01'+raw[3:], 'ShortestHead'),
        ('array-length-precheck', raw[:2]+b'\x9a\x00\x01\x86\xa1', 'Resource'),
    ]:
        add(name, good, error, fragment)
    # Thirds have no representable endpoint touch; three halves supplies the
    # exact touches with each inclusion flag. All verdicts retain their interval.
    three_halves = 0x3ff8000000000000
    negative_one = one | (1 << 63)
    negative_half = half | (1 << 63)
    negative_quarter = quarter | (1 << 63)
    for threshold, bounds in (
        (Fraction(2, 3), [(0, half), (half, one), (one, two)]),
        (Fraction(3, 2), [(0, one), (one, three_halves), (one, two), (three_halves, two), (two, two+1)]),
        (Fraction(-2, 3), [(two | (1 << 63), negative_one), (negative_one, negative_half), (negative_half, negative_quarter)]),
    ):
        for predicate in range(1, 6):
            for number, (lower, upper) in enumerate(bounds):
                for li in (False, True):
                    for ui in (False, True):
                        evaluated = interval(lower, upper, li, ui)
                        v = base(evaluated)
                        result = threshold_result(predicate, evaluated, threshold)
                        v[4] = [None, None]
                        v[6] = [predicate, q(threshold), result, 5]
                        v[7][0][2] = result
                        add(f'signed-threshold-{predicate}-{threshold}-{number}-{int(li)}{int(ui)}', v)
    for scale in (1075, 1076):
        threshold = Fraction(3, 1 << scale)
        for predicate in range(1, 6):
            v = base(interval(1))
            result = threshold_result(predicate, v[7][0][1], threshold)
            v[4] = [None, None]
            v[6] = [predicate, q(threshold), result, 5]
            v[7][0][2] = result
            add(f'subnormal-threshold-{predicate}-{scale}', v)
    v = base(interval(one)); v[4] = [None, None]; v[6] = [1, q(1), 0, 5]
    v[5] = 1
    add('threshold-adjusted-flag', v, 'Structure(Adjustment)')
    v = copy.deepcopy(v); v[5] = 0; v[4] = [interval(one), interval(one)]
    add('threshold-enclosure-pair', v, 'Structure(Adjustment)')
    add('membership-wholly-above', base(interval(two), interval(0, one)))
    raw = encode(good)
    add('reserved-head', good, 'ItemKind', raw.replace(b'\x1b'+one.to_bytes(8, 'big'), b'\x1c'+one.to_bytes(8, 'big'), 1))
    add('simple-undefined', good, 'ItemKind', raw.replace(b'\x08\xf6', b'\x08\xf7', 1))
    add('negative-integer-unsigned', good, 'ItemKind', raw.replace(b'\x05\x00', b'\x05\x20', 1))
    add('nested-map', good, 'ItemKind', raw.replace(b'\x02\x80', b'\x02\xa0', 1))
    # The earlier edition's rows remain complete values in their original order.
    def add_v2(name, value, cause=None, raw=None):
        add('positive-'+name, value, None if cause is None else ('SecondEdition('+cause+')' if cause[0].isupper() and cause not in ('UnknownCode', 'Arity', 'ItemKind') else cause), raw)
        rows[-1]['edition'] = 2
        rows[-1]['rungs'] = copy.deepcopy(value[8])

    def rung_v2(results, ending, positive=3):
        v = base(interval(0))
        v[0] = 2
        v[1] = [1, [[1, 0]], 0]
        v[3] = [[['rung', q(0), True, q(positive), True]], []]
        v[4] = [None, None]
        v[6] = [1, q(1), 0 if ending == [0] else None, 4]
        enclosures = [interval(one), interval(one+1), interval(one, one+1)]
        v[7] = [[i, enclosures[result], result] for i, result in enumerate(results)]
        v[8] = [0, [q(i) for i in range(positive, -1, -1)], [[i, i, result] for i, result in enumerate(results)]]
        v[9] = ending
        return v

    for name, results, ending, count in [
        ('pass-small', [0], [0], 1), ('pass-long', [1, 2, 0], [0], 3),
        ('anchor-small', [1], [1], 1), ('anchor-long', [2, 1, 2], [1], 3),
        ('anchor-empty', [], [1], 0), ('anchor-identical', [1, 1, 1], [1], 3),
    ]:
        add_v2(name, rung_v2(results, ending, count))
    for cause in range(1, 8):
        add_v2(f'operational-empty-{cause}', rung_v2([], [2, cause], 1))
        add_v2(f'operational-prefix-{cause}', rung_v2([2, 1], [2, cause]))
    small = rung_v2([0], [0], 1)
    prefix = rung_v2([1], [2, 1], 3)
    anchor = rung_v2([1], [1], 1)
    def bad_v2(name, change, cause, source=small):
        v = copy.deepcopy(source); change(v); add_v2(name, v, cause)
    bad_v2('predicate', lambda v: (v[6].__setitem__(0, 2), v[7][0].__setitem__(1, interval(0))), 'RungPredicate')
    bad_v2('threshold', lambda v: v[6].__setitem__(1, q(2)), 'RungThreshold')
    bad_v2('adjustment', lambda v: v.__setitem__(5, 1), 'RungAdjustment')
    bad_v2('enclosures', lambda v: v.__setitem__(4, [interval(0), interval(0)]), 'RungEnclosures')
    bad_v2('missing-rungs', lambda v: v.__setitem__(8, None), 'MissingRungs')
    bad_v2('coordinate', lambda v: v[8].__setitem__(0, 1), 'Coordinate')
    bad_v2('empty-grid', lambda v: v[8].__setitem__(1, []), 'EmptyGrid', rung_v2([], [1], 0))
    bad_v2('negative-grid', lambda v: (v[8].__setitem__(1, [q(-1), q(0)]), v[3][0][0].__setitem__(1, q(-1))), 'NegativeGrid')
    bad_v2('repeated-grid', lambda v: v[8].__setitem__(1, [q(1), q(1), q(0)]), 'GridDescent')
    bad_v2('increasing-grid', lambda v: (v[8].__setitem__(1, [q(1), q(2), q(0)]), v[3][0][0].__setitem__(3, q(2))), 'GridDescent')
    bad_v2('missing-zero', lambda v: v[8].__setitem__(1, [q(1), q(Fraction(1, 2))]), 'GridZero')
    bad_v2('grid-lower', lambda v: v[3][0][0].__setitem__(1, q(1)), 'GridLower')
    bad_v2('grid-lower-open', lambda v: v[3][0][0].__setitem__(2, False), 'GridLowerOpen')
    bad_v2('grid-upper', lambda v: v[8].__setitem__(1, [q(2), q(0)]), 'GridUpper')
    bad_v2('grid-upper-open', lambda v: v[3][0][0].__setitem__(4, False), 'GridUpperOpen')
    bad_v2('row-index', lambda v: v[8][2][0].__setitem__(0, 1), 'RowIndex')
    bad_v2('test-index', lambda v: v[8][2][0].__setitem__(1, 1), 'TestIndex')
    bad_v2('missing-test', lambda v: v.__setitem__(7, []), 'MissingTest', prefix)
    bad_v2('subject', lambda v: v[7][0].__setitem__(0, 1), 'Subject')
    bad_v2('row-result', lambda v: v[8][2][0].__setitem__(2, 1), 'RowResult')
    bad_v2('lower-fence', lambda v: v[7][0].__setitem__(1, interval(0, one, li=False)), 'LowerFence')
    bad_v2('upper-fence', lambda v: v[7][0].__setitem__(1, interval(0, one, ui=False)), 'UpperFence')
    for result in (1, 2):
        bad_v2(f'verdict-{result}', lambda v: v[7][0].__setitem__(1, interval(one+1) if result == 1 else interval(one, one+1)), 'TestVerdict')
    bad_v2('anchor-row', lambda v: None, 'AnchorRow', rung_v2([1, 0], [0], 1))
    bad_v2('zero-only-row', lambda v: None, 'AnchorRow', rung_v2([0], [0], 0))
    bad_v2('after-pass', lambda v: None, 'AfterPass', rung_v2([0, 0], [0], 3))
    bad_v2('extra-test', lambda v: v[7].append([1, interval(one+1), 1]), 'TestCount')
    bad_v2('missing-pass', lambda v: (v.__setitem__(9, [0]), v[6].__setitem__(2, 0)), 'MissingPass', prefix)
    bad_v2('incomplete-anchor', lambda v: v.__setitem__(9, [1]), 'IncompleteAnchor', prefix)
    bad_v2('anchor-pass', lambda v: (v.__setitem__(9, [1]), v[6].__setitem__(2, None)), 'AnchorPass')
    bad_v2('full-operational', lambda v: v.__setitem__(9, [2, 1]), 'CompleteOperational', anchor)
    bad_v2('operational-pass', lambda v: v[6].__setitem__(2, None), 'OperationalPass', rung_v2([0], [2, 1], 3))
    for cause in (0, 8):
        bad_v2(f'cause-{cause}', lambda v: v.__setitem__(9, [2, cause]), 'Cause', prefix)
    for sign in (None, 1, 2):
        bad_v2(f'pass-polarity-{sign}', lambda v: v[6].__setitem__(2, sign), 'PassPolarity')
    bad_v2('anchor-polarity', lambda v: v[6].__setitem__(2, 0), 'AnchorPolarity', anchor)
    bad_v2('operational-polarity', lambda v: v[6].__setitem__(2, 2), 'OperationalPolarity', prefix)
    bad_v2('unknown-ending', lambda v: v.__setitem__(9, [3]), 'UnknownCode')
    bad_v2('ending-arity', lambda v: v.__setitem__(9, [1, 0]), 'Arity')
    # Adjacent-level overlaps make precedence observable, separately from isolated guards.
    bad_v2('order-framing-question', lambda v: (v.__setitem__(0, 1), v[6].__setitem__(0, 2)), 'UnknownCode')
    bad_v2('order-question-grid', lambda v: (v[6].__setitem__(0, 2), v[8].__setitem__(1, [])), 'RungPredicate')
    bad_v2('order-grid-row', lambda v: (v[8].__setitem__(1, [q(1), q(1), q(0)]), v[7][0].__setitem__(0, 1)), 'GridDescent')
    bad_v2('order-row-ending', lambda v: (v[7][0].__setitem__(0, 1), v.__setitem__(9, [1])), 'Subject')
    bad_v2('order-ending-polarity', lambda v: v.__setitem__(9, [1]), 'AnchorPass')
    single = base(interval(0)); single[0] = 2; single[9] = [0]
    add_v2('single-complete', single)
    for cause in range(1, 8):
        v = copy.deepcopy(single); v[7] = []; v[6][2] = None; v[9] = [2, cause]
        add_v2(f'single-operational-{cause}', v)
    bad_v2('single-anchor', lambda v: (v.__setitem__(9, [1]), v[6].__setitem__(2, None)), 'NonRungAnchor', single)
    bad_v2('single-count', lambda v: (v.__setitem__(7, []), v[6].__setitem__(2, None)), 'SingleCount', single)
    bad_v2('single-subject', lambda v: v[7][0].__setitem__(0, 0), 'SingleSubject', single)
    bad_v2('single-polarity', lambda v: v[6].__setitem__(2, 1), 'SinglePolarity', single)
    bad_v2('single-operational-tests', lambda v: (v.__setitem__(9, [2, 1]), v[6].__setitem__(2, None)), 'OperationalTests', single)
    bad_v2('non-rung-data', lambda v: (v[6].__setitem__(3, 0), v[7][0].__setitem__(0, None)), 'NonRungData')

    bad_v2('membership-enclosures', lambda v: v.__setitem__(4, [None, None]), 'MembershipEnclosures', single)
    bad_v2('membership-adjustment', lambda v: v.__setitem__(5, 1), 'Adjustment', single)
    threshold = copy.deepcopy(single); threshold[4] = [None, None]; threshold[6] = [1, q(1), 0, 5]
    add_v2('single-threshold', threshold)
    bad_v2('threshold-enclosures', lambda v: v.__setitem__(4, [interval(0), interval(0)]), 'ThresholdEnclosures', threshold)
    bad_v2('threshold-adjustment', lambda v: v.__setitem__(5, 1), 'ThresholdAdjustment', threshold)
    bad_v2('consumer-predicate', lambda v: v[6].__setitem__(3, 1), 'ConsumerPredicate', threshold)
    bad_v2('fixed-predicate', lambda v: v[6].__setitem__(3, 5), 'FixedPredicate', single)
    negative = base(interval(one), interval(0)); negative[0] = 2; negative[9] = [0]
    bad_v2('consumer-polarity', lambda v: v[6].__setitem__(3, 1), 'ConsumerPolarity', negative)
    bad_v2('single-operational-polarity', lambda v: v[6].__setitem__(2, 2), 'OperationalPolarity', {**copy.deepcopy(single), 7: [], 9: [2, 1], 6: [0, None, None, 0]})
    bad_v2('single-verdict', lambda v: v[7][0].__setitem__(1, interval(one)), 'TestVerdict', single)
    for cause in (0, 8):
        bad_v2(f'single-cause-{cause}', lambda v: v.__setitem__(9, [2, cause]), 'Cause', {**copy.deepcopy(single), 7: [], 9: [2, 1], 6: [0, None, None, 0]})
    for claimed, supplied in ((1, 0), (1, 2), (2, 0), (2, 1)):
        source = rung_v2([claimed], [2, 1], 3)
        enclosures = [interval(one), interval(one+1), interval(one, one+1)]
        bad_v2(f'verdict-{claimed}-from-{supplied}', lambda v: v[7][0].__setitem__(1, enclosures[supplied]), 'TestVerdict', source)
    bad_v2('repeated-row', lambda v: v[8][2][1].__setitem__(0, 0), 'RowIndex', rung_v2([1, 2, 0], [0], 3))
    bad_v2('reordered-row', lambda v: (v[8][2][0].__setitem__(0, 1), v[8][2][1].__setitem__(0, 0)), 'RowIndex', rung_v2([1, 2, 0], [0], 3))
    bad_v2('zero-only-complete', lambda v: (v.__setitem__(9, [0]), v[6].__setitem__(2, 0)), 'MissingPass', rung_v2([], [1], 0))
    bad_v2('zero-only-operational', lambda v: v.__setitem__(9, [2, 1]), 'CompleteOperational', rung_v2([], [1], 0))
    for name, ending in [('complete-extra', [0, 1]), ('operational-missing', [2]), ('operational-extra', [2, 1, 1])]:
        bad_v2(name, lambda v: v.__setitem__(9, ending), 'Arity')
    # Within-level overlaps witness first-refusal precedence; no verdict is detached from its enclosure.
    bad_v2('within-predicate-threshold', lambda v: (v[6].__setitem__(0, 2), v[6].__setitem__(1, q(2))), 'RungPredicate')
    bad_v2('within-threshold-adjustment', lambda v: (v[6].__setitem__(1, q(2)), v.__setitem__(5, 1)), 'RungThreshold')
    bad_v2('within-adjustment-enclosures', lambda v: (v.__setitem__(5, 1), v.__setitem__(4, [interval(0), interval(0)])), 'RungAdjustment')
    bad_v2('within-negative-descent', lambda v: (v[8].__setitem__(1, [q(-1), q(0)]), v[3][0][0].__setitem__(1, q(-2))), 'NegativeGrid')
    bad_v2('within-descent-zero', lambda v: v[8].__setitem__(1, [q(1), q(1)]), 'GridDescent')
    bad_v2('within-zero-domain', lambda v: (v[8].__setitem__(1, [q(3), q(2)]), v[3][0][0].__setitem__(slice(1, 5), [q(4), True, q(5), True])), 'GridZero')
    bad_v2('within-domain-members', lambda v: (v[8].__setitem__(1, [q(2), q(0)]), v[3][0][0].__setitem__(slice(1, 5), [q(Fraction(1, 2)), True, q(Fraction(3, 2)), True])), 'GridUpper')
    bad_v2('within-row-test-index', lambda v: v[8][2][0].__setitem__(slice(0, 2), [1, 1]), 'RowIndex')
    bad_v2('within-test-index-missing', lambda v: (v[8][2][0].__setitem__(1, 1), v.__setitem__(7, [])), 'TestIndex', prefix)
    bad_v2('within-subject-result', lambda v: (v[7][0].__setitem__(0, 1), v[8][2][0].__setitem__(2, 1)), 'Subject')
    bad_v2('within-result-lower', lambda v: (v[8][2][0].__setitem__(2, 1), v[7][0].__setitem__(1, interval(0, one, li=False))), 'RowResult')
    bad_v2('within-lower-upper', lambda v: v[7][0].__setitem__(1, interval(0, one, li=False, ui=False)), 'LowerFence')
    bad_v2('within-upper-verdict', lambda v: v[7][0].__setitem__(1, interval(0, two, ui=False)), 'UpperFence')
    bad_v2('within-verdict-anchor', lambda v: v[7][0].__setitem__(1, interval(one, one+1)), 'TestVerdict', rung_v2([0], [0], 0))
    bad_v2('within-anchor-after-pass', lambda v: None, 'AnchorRow', rung_v2([0, 0], [0], 1))
    bad_v2('within-count-complete', lambda v: v[7].append([1, interval(one+1), 1]), 'TestCount', rung_v2([1], [0], 3))
    bad_v2('within-count-anchor', lambda v: v[7].append([1, interval(one+1), 1]), 'TestCount', rung_v2([1], [1], 3))
    bad_v2('within-count-operational', lambda v: v[7].append([1, interval(one+1), 1]), 'TestCount', rung_v2([1], [2, 1], 1))
    bad_v2('within-anchor-count-pass', lambda v: v[6].__setitem__(2, None), 'IncompleteAnchor', rung_v2([0], [1], 3))
    bad_v2('within-operational-count-pass', lambda v: v[6].__setitem__(2, None), 'CompleteOperational', rung_v2([0], [2, 1], 1))
    bad_v2('within-operational-pass-cause', lambda v: v[6].__setitem__(2, None), 'OperationalPass', rung_v2([0], [2, 8], 3))
    bad_v2('within-single-subject-verdict', lambda v: (v[7][0].__setitem__(0, 0), v[7][0].__setitem__(1, interval(one))), 'SingleSubject', single)
    bad_v2('within-single-tests-cause', lambda v: (v.__setitem__(9, [2, 8]), v[6].__setitem__(2, None)), 'OperationalTests', single)
    bad_v2('within-single-polarities', lambda v: (v[6].__setitem__(3, 1), v[6].__setitem__(2, 1)), 'SinglePolarity', single)
    bad_v2('anchor-one-short', lambda v: None, 'IncompleteAnchor', rung_v2([1, 2], [1], 3))
    bad_v2('single-two-tests', lambda v: v[7].append(copy.deepcopy(v[7][0])), 'SingleCount', single)
    # Active non-rung levels and key references retain the same first-refusal contract.
    bad_v2('within-single-subject-count', lambda v: (v[7].append(copy.deepcopy(v[7][0])), v[7][0].__setitem__(0, 0)), 'SingleSubject', single)
    bad_v2('within-single-subject-anchor', lambda v: (v[7][0].__setitem__(0, 0), v.__setitem__(9, [1]), v[6].__setitem__(2, None)), 'SingleSubject', single)
    bad_v2('within-coordinate-empty', lambda v: (v[8].__setitem__(0, 1), v[8].__setitem__(1, [])), 'Coordinate', rung_v2([], [1], 0))
    bad_v2('within-enclosures-missing-rungs', lambda v: (v.__setitem__(4, [interval(0), interval(0)]), v.__setitem__(8, None)), 'RungEnclosures')
    bad_v2('within-threshold-enclosures-consumer', lambda v: (v.__setitem__(4, [interval(0), interval(0)]), v[6].__setitem__(3, 1)), 'ThresholdEnclosures', threshold)
    bad_v2('within-threshold-adjustment-consumer', lambda v: (v.__setitem__(5, 1), v[6].__setitem__(3, 1)), 'ThresholdAdjustment', threshold)
    bad_v2('within-fixed-data', lambda v: (v[6].__setitem__(3, 5), v.__setitem__(8, copy.deepcopy(small[8]))), 'FixedPredicate', single)
    bad_v2('within-membership-enclosures-fixed', lambda v: (v.__setitem__(4, [None, None]), v[6].__setitem__(3, 5)), 'MembershipEnclosures', single)
    bad_v2('within-membership-adjustment-fixed', lambda v: (v.__setitem__(5, 1), v[6].__setitem__(3, 5)), 'Adjustment', single)
    bad_v2('within-consumer-data', lambda v: (v[6].__setitem__(3, 1), v.__setitem__(8, copy.deepcopy(small[8]))), 'ConsumerPredicate', threshold)
    bad_v2('order-single-question-test', lambda v: (v.__setitem__(5, 1), v[7][0].__setitem__(0, 0)), 'ThresholdAdjustment', threshold)
    bad_v2('order-single-test-ending', lambda v: (v[7].append(copy.deepcopy(v[7][0])), v[7][0].__setitem__(1, interval(one))), 'TestVerdict', single)
    bad_v2('order-single-ending-polarity', lambda v: (v[7].append(copy.deepcopy(v[7][0])), v[6].__setitem__(2, 1)), 'SingleCount', single)
    bad_v2('instance-rung-verdict-index', lambda v: (v[7][0].__setitem__(1, interval(one)), v[8][2][1].__setitem__(0, 0)), 'TestVerdict', rung_v2([1, 0], [0], 2))
    bad_v2('instance-single-verdict-subject', lambda v: (v[7].append(copy.deepcopy(v[7][0])), v[7][0].__setitem__(1, interval(one)), v[7][1].__setitem__(0, 0)), 'TestVerdict', single)
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
