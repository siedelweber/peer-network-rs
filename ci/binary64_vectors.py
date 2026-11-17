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



def comparison_vectors():
    """Exact-rational comparison fragments; no claim of an enclosure's soundness."""
    rows = []
    def verdict(predicate, lower, li, upper, ui):
        signs = set()
        if lower < 0: signs.add(-1)
        if upper > 0: signs.add(1)
        if lower <= 0 <= upper and (lower != 0 or li) and (upper != 0 or ui): signs.add(0)
        allowed = {1: {-1, 0}, 2: {-1}, 3: {0}, 4: {0, 1}, 5: {1}}[predicate]
        return 0 if signs <= allowed else 1 if signs.isdisjoint(allowed) else 2
    def relation(lower, li, upper, ui):
        return 0 if upper < 0 or upper == 0 and not ui else 2 if lower > 0 or lower == 0 and not li else 1 if lower == upper == 0 else 3
    def evaluated(predicate=1, lower=-1, upper=1, li=True, ui=True, reduction=0):
        return [2, [0, reduction, predicate, [q(lower), li, q(upper), ui], q(0), relation(lower, li, upper, ui), verdict(predicate, lower, li, upper, ui)]]
    def exact_value(predicate=1, left=1, right=2):
        order = -1 if left < right else 1 if left > right else 0
        allowed = {1: {-1, 0}, 2: {-1}, 3: {0}, 4: {0, 1}, 5: {1}}[predicate]
        return [2, [1, q(left), predicate, q(right), order+1, 0 if order in allowed else 1]]
    def row(name, value, result='valid', *, edition='floor', question=None, expected=None, proof='valid', raw=None, rule=None):
        inner = value[1] if edition == 'floor' else value[4][1]
        if not isinstance(inner,list): inner=evaluated()[1]
        constructor = inner[0]
        question = copy.deepcopy(question or (['1', 'ridge'] if constructor == 0 else ['1', '2']))
        reduction=inner[1] if constructor == 0 and type(inner[1]) is int else 0
        predicate=inner[2] if constructor in (0,1) and type(inner[2]) is int else 1
        expected = copy.deepcopy(expected or dict(question=question, reduction=reduction, predicate=predicate, threshold=q(0)))
        rows.append(dict(case=name, edition=edition, question=question, expected=expected, proof=proof, value=copy.deepcopy(value), canonical=(encode(value) if raw is None else raw).hex(), result=result, rule=rule or name))
    def bad(name, mutate, cause, source=None, **kwargs):
        value = copy.deepcopy(source or evaluated())
        mutate(value)
        row(name, value, cause, **kwargs)
    intervals=[(-2,-1,True,True),(0,0,True,True),(1,2,True,True),(-1,1,True,True),(-1,0,True,True),(-1,0,True,False),(0,1,True,True),(0,1,False,True)]
    for reduction in (0,1):
        for predicate in range(1,6):
            for index, bounds in enumerate(intervals):
                row(f'evaluated-{reduction}-{predicate}-{index}', evaluated(predicate,*bounds,reduction=reduction), question=['1/10','ridge'] if reduction else None)
    for predicate in range(1,6):
        for left,right in [(1,2),(2,2),(3,2),(-2,Fraction(-1,3))]:
            row(f'exact-{predicate}-{left}-{right}', exact_value(predicate,left,right), question=[str(left),str(right)])
    for cause in range(1,8): row(f'operational-{cause}', [2,[2,cause]])
    base=evaluated()
    expected=dict(question=['1','ridge'],reduction=0,predicate=1,threshold=q(0))
    exact_expected={**expected,'question':['1','2']}
    bad('unknown-reduction',lambda v:v[1].__setitem__(1,2),'Reduction')
    for predicate in (0,6): bad(f'unknown-predicate-{predicate}',lambda v:v[1].__setitem__(2,predicate),'Predicate')
    row('question-left',base,'QuestionLeft',expected={**expected,'question':['2','ridge']})
    row('question-right',base,'QuestionRight',expected={**expected,'question':['1','3']})
    row('expected-reduction',base,'ExpectedReduction',expected={**expected,'reduction':1})
    row('expected-predicate',base,'ExpectedPredicate',expected={**expected,'predicate':2})
    row('expected-threshold',base,'ExpectedThreshold',expected={**expected,'threshold':q(1)})
    bad('enclosure-order',lambda v:v[1].__setitem__(3,[q(1),True,q(-1),True]),'EnclosureOrder')
    for side,cause in ((1,'LowerInclusion'),(3,'UpperInclusion')):
        bad(cause,lambda v:v[1][3].__setitem__(side,False),cause,evaluated(lower=0,upper=0))
    bad('threshold',lambda v:v[1].__setitem__(4,q(1)),'Threshold',expected={**expected,'threshold':q(1)})
    bad('relation-code',lambda v:v[1].__setitem__(5,4),'Relation')
    bad('relation-agreement',lambda v:v[1].__setitem__(5,0),'RelationAgreement')
    bad('verdict-code',lambda v:v[1].__setitem__(6,3),'Verdict')
    bad('verdict-agreement',lambda v:v[1].__setitem__(6,0),'VerdictAgreement')
    ex=exact_value()
    row('exact-context',ex,'ExactContext',question=['1','ridge'])
    bad('exact-left',lambda v:v[1].__setitem__(1,q(0)),'ExactLeft',ex)
    bad('exact-right',lambda v:v[1].__setitem__(3,q(3)),'ExactRight',ex)
    bad('exact-relation-code',lambda v:v[1].__setitem__(4,4),'Relation',ex)
    bad('exact-unresolved',lambda v:v[1].__setitem__(4,3),'ExactUnresolved',ex)
    bad('exact-relation-agreement',lambda v:v[1].__setitem__(4,2),'RelationAgreement',ex)
    bad('exact-verdict-code',lambda v:v[1].__setitem__(5,3),'Verdict',ex)
    bad('exact-indecisive',lambda v:v[1].__setitem__(5,2),'ExactIndecisive',ex)
    bad('exact-verdict-agreement',lambda v:v[1].__setitem__(5,1),'VerdictAgreement',ex)
    for cause in (0,8): row(f'operational-cause-{cause}',[2,[2,cause]],'Cause')
    derivative=evaluated(reduction=1)
    for name,question,cause in [('derivative-left',['ridge','ridge'],'DerivativeLeft'),('derivative-right',['1/10','2'],'DerivativeRight'),('wall-zero',['0','ridge'],'WallLower'),('wall-negative',['-1','ridge'],'WallLower'),('wall-one',['1','ridge'],'WallUpper'),('wall-above',['2','ridge'],'WallUpper'),('definition',['1/10','foreign-ridge'],'Definition')]:
        row(name,derivative,cause,question=question)
    for mode,cause in [('missing','MissingProof'),('foreign','ProofIdentity'),('incomplete','Proof'),('invalid','Proof')]:
        row(f'proof-{mode}',derivative,cause,question=['1/10','ridge'],proof=mode)
    # Syntax rows have no verdict claim; their malformed member prevents downstream interpretation.
    for name,mutate,cause in [
        ('edition',lambda v:v.__setitem__(0,1),'Edition'),
        ('outer-arity',lambda v:v.append(0),'Arity'),
        ('constructor',lambda v:v[1].__setitem__(0,3),'Constructor'),
        ('result-arity',lambda v:v[1].append(0),'Arity'),
        ('missing-enclosure',lambda v:v[1].__setitem__(3,None),'Member'),
        ('enclosure-arity',lambda v:v[1][3].pop(),'Arity'),
        ('threshold-kind',lambda v:v[1].__setitem__(4,None),'Member'),
        ('number-spelling',lambda v:v[1][4].__setitem__(0,'00'),'Number'),
        ('number-reduction',lambda v:v[1].__setitem__(4,['0','2']),'Number'),
        ('number-kind',lambda v:v[1][4].__setitem__(0,0),'Member'),
        ('constructor-kind',lambda v:v[1].__setitem__(0,'0'),'Member'),
        ('reduction-kind',lambda v:v[1].__setitem__(1,False),'Member'),
        ('result-kind',lambda v:v.__setitem__(1,None),'Member'),
        ('number-arity',lambda v:v[1][4].append('1'),'Arity'),
        ('inclusion-kind',lambda v:v[1][3].__setitem__(1,0),'Member'),
    ]:bad(name,mutate,cause)
    raw=encode(base)
    row('trailing',base,'TrailingBytes',raw=raw+b'\x00')
    row('longer-head',base,'NonPreferredHead',raw=b'\x98\x02'+raw[1:])
    row('indefinite',base,'IndefiniteLength',raw=b'\x9f'+raw[1:]+b'\xff')
    row('tag',base,'Tag',raw=b'\xc0'+raw)
    row('float',base,'Float',raw=b'\xf9\x00\x00')
    row('negative-cause-kind',[2,[2,1]],'Member',raw=b'\x82\x02\x82\x02\x20')
    # These overlap pairs are jointly invalid; the named earlier clause owns their stored refusal.
    bad('order-question-reduction',lambda v:v[1].__setitem__(1,2),'QuestionLeft',expected={**expected,'question':['2','ridge']})
    bad('order-domain-enclosure',lambda v:v[1].__setitem__(3,[q(1),True,q(-1),True]),'WallLower',derivative,question=['0','ridge'])
    bad('order-enclosure-relation',lambda v:(v[1].__setitem__(3,[q(1),True,q(-1),True]),v[1].__setitem__(5,4)),'EnclosureOrder')
    bad('order-relation-verdict',lambda v:(v[1].__setitem__(5,0),v[1].__setitem__(6,0)),'RelationAgreement')
    row('order-question-operational', [2,[2,8]], 'QuestionLeft', expected={**expected,'question':['2','ridge']})
    # Inherited ridge projections use their independent existing integer/text encodings.
    def ridge(comparison): return [2,[0,['1/10',q(Fraction(1,10))]],[0],[],comparison,'0']
    rational_question=['1/10','3/37']
    for index,comparison in enumerate([evaluated(1,-1,-1),evaluated(1,1,1),evaluated(),exact_value(1,Fraction(1,10),Fraction(3,37))]+[[2,[2,c]] for c in range(1,8)]):
        value=ridge(comparison)
        if comparison[1][0] == 0: value[2]=[1]
        row(f'ridge-{index}',value,edition='ridge',question=['1/10','ridge'] if comparison[1][0] == 0 else rational_question)
    for name,mutate,cause in [('outer-edition',lambda v:v.__setitem__(0,1),'Edition'),('outer-size',lambda v:v.append(0),'Arity'),('nested-edition',lambda v:v[4].__setitem__(0,1),'Edition'),('wall-binding',lambda v:v.__setitem__(1,[0,['1/9',q(Fraction(1,9))]]),'WallBinding'),('floor-binding',lambda v:v.__setitem__(2,[1]),'FloorBinding'),('queries-not-enclosure',lambda v:v[4][1].__setitem__(3,[]),'Arity')]:
        value=ridge(evaluated());mutate(value)
        row('ridge-'+name,value,cause,edition='ridge',question=rational_question)
    for predicate in range(1,6):
        row(f'identity-ridge-{predicate}',evaluated(predicate),question=['1/10','ridge'])
    row('identity-symbolic-left',evaluated(),question=['ridge','1'])
    row('identity-symbolic-both',evaluated(),question=['ridge','ridge'])
    row('identity-number',evaluated(),'Number',question=['not-a-number','ridge'])
    row('identity-instance-definition-number',evaluated(),'Definition',question=['foreign-ridge','not-a-number'])
    row('within-question-left-right',base,'QuestionLeft',expected={**expected,'question':['2','3']})
    bad('within-reduction-predicate',lambda v:(v[1].__setitem__(1,2),v[1].__setitem__(2,0)),'Reduction')
    bad('within-predicate-expected-reduction',lambda v:v[1].__setitem__(2,0),'Predicate',expected={**expected,'reduction':1})
    row('within-expected-reduction-predicate',base,'ExpectedReduction',expected={**expected,'reduction':1,'predicate':2})
    row('within-expected-predicate-domain',derivative,'ExpectedPredicate',question=['0','ridge'],expected=dict(question=['0','ridge'],reduction=1,predicate=2,threshold=q(0)))
    row('within-derivative-left-right',derivative,'DerivativeLeft',question=['ridge','2'])
    row('within-derivative-right-lower',derivative,'DerivativeRight',question=['0','2'])
    row('within-upper-definition',derivative,'WallUpper',question=['1','foreign-ridge'])
    row('within-definition-proof',derivative,'Definition',question=['1/10','foreign-ridge'],proof='missing')
    bad('within-lower-upper-inclusion',lambda v:(v[1][3].__setitem__(1,False),v[1][3].__setitem__(3,False)),'LowerInclusion',evaluated(lower=0,upper=0))
    bad('within-upper-threshold',lambda v:(v[1][3].__setitem__(3,False),v[1].__setitem__(4,q(1))),'UpperInclusion',evaluated(lower=0,upper=0),expected={**expected,'threshold':q(1)})
    bad('within-threshold-binding',lambda v:v[1].__setitem__(4,q(1)),'Threshold',expected={**expected,'threshold':q(2)})
    bad('within-relation-verdict-code',lambda v:(v[1].__setitem__(5,0),v[1].__setitem__(6,3)),'RelationAgreement')
    bad('order-expected-threshold-relation',lambda v:v[1].__setitem__(5,4),'ExpectedThreshold',expected={**expected,'threshold':q(1)})
    bad('order-predicate-enclosure',lambda v:(v[1].__setitem__(2,0),v[1].__setitem__(3,[q(1),True,q(-1),True])),'Predicate')
    bad('order-edition-question',lambda v:v.__setitem__(0,1),'Edition',expected={**expected,'question':['2','ridge']})
    bad('within-exact-left-right',lambda v:(v[1].__setitem__(1,q(0)),v[1].__setitem__(3,q(3))),'ExactLeft',ex)
    bad('within-exact-right-predicate',lambda v:(v[1].__setitem__(3,q(3)),v[1].__setitem__(2,0)),'ExactRight',ex)
    bad('within-exact-predicate-binding',lambda v:v[1].__setitem__(2,0),'Predicate',ex,expected=exact_expected)
    bad('order-exact-binding-relation',lambda v:v[1].__setitem__(4,4),'ExpectedPredicate',ex,expected={**exact_expected,'predicate':2})
    bad('within-exact-relation-verdict',lambda v:(v[1].__setitem__(4,2),v[1].__setitem__(5,3)),'RelationAgreement',ex)
    # The unchanged publication schema names 37 BudgetUsage members, each decimal text.
    primitive=[[[],[[0,['0',q(0)]]],'0',[0]],'1',[[5],None,None,'0',['0']*37,'0',False,'0',None]]
    value=ridge(evaluated());value[2]=[1];value[3]=[copy.deepcopy(primitive),copy.deepcopy(primitive)]
    row('ridge-query-pair',value,edition='ridge',question=['1/10','ridge'])
    value[3][0][0][1][0][1]=['0',['0','2']]
    value[3][1][0][0]={}
    row('ridge-query-instance-number-shape',value,'Projection::CanonicalNumber',edition='ridge',question=['1/10','ridge'])
    value=ridge(evaluated());value[1][1][1]=['1','20'];value[2]=[2]
    row('ridge-projection-wall-floor',value,'Projection::CanonicalNumber',edition='ridge',question=rational_question)
    value=ridge(evaluated());value[1]=[0,['1/9',q(Fraction(1,9))]];value[2]=[1]
    row('ridge-binding-wall-floor',value,'WallBinding',edition='ridge',question=rational_question)
    value=ridge(evaluated());value[2]=[1];value[4][1][1]=2
    row('ridge-binding-nested-reduction',value,'FloorBinding',edition='ridge',question=rational_question)
    value=ridge(evaluated());value[0]=1;value[1]=[0,['1/9',q(Fraction(1,9))]]
    row('ridge-order-edition-wall',value,'Edition',edition='ridge',question=rational_question)
    for reduction in (0,1):
        for predicate in range(1,6):
            for index,bounds in enumerate(intervals[:4]):
                value=ridge(evaluated(predicate,*bounds,reduction=reduction));value[2]=[1]
                row(f'ridge-symbolic-{reduction}-{predicate}-{index}',value,edition='ridge',question=['1/10','ridge'])
    value=ridge(exact_value(1,Fraction(1,10),Fraction(3,37)));value[2]=[1]
    row('ridge-exact-symbolic',value,'ExactContext',edition='ridge',question=['1/10','ridge'])
    row('ridge-rounded-floor',ridge(evaluated()),'FloorBinding',edition='ridge',question=['1/10','ridge'])
    for existing in rows:
        if existing['case'] == 'ridge-queries-not-enclosure':
            existing['value'][3]=[copy.deepcopy(primitive),copy.deepcopy(primitive)]
            existing['canonical']=encode(existing['value']).hex()
    # Exact operands use the exact constructor; the enclosure cannot change that fact.
    row('evaluated-exact-context',evaluated(),'ExactEvaluated',question=['1','2'])
    row('order-domain-exact-context',evaluated(),'Number',question=['1','not-a-number'])
    bad('order-exact-context-enclosure',lambda v:v[1].__setitem__(3,[q(1),True,q(-1),True]),'ExactEvaluated',question=['1','2'])
    row('ridge-evaluated-exact-context',ridge(evaluated()),'ExactEvaluated',edition='ridge',question=rational_question)
    value=ridge(evaluated());value[4][1][3]=[q(1),True,q(-1),True]
    row('ridge-order-exact-context-enclosure',value,'ExactEvaluated',edition='ridge',question=rational_question)
    row('operational-with-verdict',[2,[2,1,2]],'Arity')
    row('ridge-operational-with-verdict',ridge([2,[2,1,2]]),'Arity',edition='ridge',question=rational_question)
    for code in (1,2,3):
        value=evaluated(lower=-1,upper=-1);value[1][5]=code
        row(f'relation-agreement-{code}',value,'RelationAgreement')
        nested=ridge(value);nested[2]=[1]
        row(f'ridge-relation-agreement-{code}',nested,'RelationAgreement',edition='ridge',question=['1/10','ridge'])
    # Deterministic unsorted delivery avoids hiding a traversal defect behind fixture sorting.
    rows=rows[::2][::-1]+rows[1::2]
    return dict(provenance='Independent integer encoder and exact Fraction endpoint signs; no codec or interchange imports, no enclosure soundness or native-law evidence.',distinct_inputs=len({json.dumps({k:v for k,v in r.items() if k in ('canonical','edition','question','expected','proof')},sort_keys=True) for r in rows}),distinct_byte_inputs=len({r['canonical'] for r in rows}),cases=rows)


def controller_vectors():
    """Fresh contextual fixtures; only integer encoding and exact Fraction signs."""
    rows = []
    def source(value): return [str(value), q(value)]
    def rng(lower, upper): return [source(lower), source(upper)]
    def evaluated(predicate=4, lower=-1, upper=1, li=True, ui=True):
        lower, upper = Fraction(lower), Fraction(upper)
        signs = ({-1} if lower < 0 else set()) | ({1} if upper > 0 else set())
        if lower <= 0 <= upper and (lower != 0 or li) and (upper != 0 or ui): signs.add(0)
        allowed = {1:{-1,0},2:{-1},3:{0},4:{0,1},5:{1}}[predicate]
        verdict = 0 if signs <= allowed else 1 if signs.isdisjoint(allowed) else 2
        relation = 0 if upper < 0 or upper == 0 and not ui else 2 if lower > 0 or lower == 0 and not li else 1 if lower == upper == 0 else 3
        return [2,[0,0,predicate,[q(lower),li,q(upper),ui],q(0),relation,verdict]]
    def exact(predicate, left, right):
        left,right=Fraction(left),Fraction(right)
        order=-1 if left<right else 1 if left>right else 0
        return [2,[1,q(left),predicate,q(right),order+1,0 if order in {1:{-1,0},2:{-1},3:{0},4:{0,1},5:{1}}[predicate] else 1]]
    def fraction(value): return Fraction(int(value[0]),int(value[1]))
    def foreign_predicate(value):
        enclosure=value[1][3]
        value[1]=evaluated({1:2,2:1,4:5}[value[1][2]],fraction(enclosure[0]),fraction(enclosure[2]),enclosure[1],enclosure[3])[1]
    def foreign_threshold(value):
        enclosure=value[1][3]
        enclosure[0]=q(fraction(enclosure[0])+1);enclosure[2]=q(fraction(enclosure[2])+1)
        value[1][4]=q(1)
    def foreign_exact(value,side):
        left=Fraction(9) if side==1 else fraction(value[1][1])
        right=Fraction(9) if side==3 else fraction(value[1][3])
        value[1]=exact(value[1][2],left,right)[1]
    def foreign_exact_position(value,position,side):
        branches=value[5];foreign_exact(branches[position],side)
        if branches[2][1][5]==0:
            ideal=Fraction(1,4);branches[3]=branches[4]=branches[5]=None
        elif branches[3][1][5]==0 or branches[4][1][5]==0:
            ideal=Fraction(1,4)+(-1 if branches[5][1][5]==0 else 1)*Fraction(1,8)
        else:
            ideal=Fraction(3,37)
        branches[7]=rng(ideal,ideal);value[6]=source(ideal)
    def inputs(**changes):
        data=dict(width='0',previous='1/4',floor=0,absolute_cap='1/2',relative_cap='1/2',deadband='1/10',delivery='exact',quantum='1/10',maximum_error='1/10')
        data.update(changes)
        return data
    def input_value(data):
        return [source(data['width']),False,source('0'),source('1'),source('1/400'),source(data['previous']),[data['floor']],source(data['absolute_cap']),source(data['relative_cap']),source(data['deadband']),rng('1/20','3/4'),source('1/100'),'10','1000000','1000000',[0] if data['delivery']=='exact' else [1,source(data['quantum']),source(data['maximum_error'])]]
    def procedure(name='controller-carrier', precision=None):
        return [['controller','carrier','1'],'0',name,'exact',[],[2,[str(n) for n in (precision or [8,16,24])]], [0],[],source('2'),'1000000','1000000','1000000','10',source('1/100'),None,None]
    def inverse(lower='1/2',upper='3/4'):
        return [rng(lower,upper),[],'0',[],None,False,'0']
    def point(value='1/4',floor=0,comparison=None):
        return [2,[0,source(value)],[floor],[],comparison or exact(4,value,'3/37'),'0']
    def operational(stage=1,cause=5):
        value=[2,'8',[stage],None,[],None,None,None,[2,[stage],cause]]
        if stage>=3:
            branches=zero_branches(inputs())
            for index in {3:(3,4,5),4:(3,4),5:(4,),6:()}[stage]:branches[index]=None
            if stage!=6:branches[7]=None
            value[5]=branches
        return value
    def zero_branches(data):
        p=Fraction(data['previous']);f=Fraction(3,37);distance=abs(f-p)
        cap=min(Fraction(data['absolute_cap']),Fraction(data['relative_cap'])*p)
        hold=distance<=Fraction(data['deadband'])*p
        ideal=p if hold else p-cap if distance>=cap and f<p else p+cap if distance>=cap else f
        return [True,None,exact(1,distance,Fraction(data['deadband'])*p),None if hold else exact(4,distance,data['absolute_cap']),None if hold else exact(4,distance,Fraction(data['relative_cap'])*p),None if hold else exact(2,f,p),rng(f,f),rng(ideal,ideal)]
    def delivered(data=None):
        data=data or inputs();branches=zero_branches(data)
        return [2,'8',None,None,[],branches,source(branches[7][0][0]),rng(0,0),[0]]
    def positive_branches():
        return [False,evaluated(4,0,1,False),evaluated(1,1,2),evaluated(4,-2,-1),evaluated(4,-2,-1),evaluated(2,1,2),rng('1/2','3/4'),rng('1/2','3/4')]
    def positive_delivered():
        return [2,'8',None,inverse(),[],positive_branches(),source('1/2'),rng(0,0),[0]]
    def stopped(stage=2):
        branches=positive_branches()
        for index in {0:(1,2,3,4,5),2:(2,3,4,5),3:(3,4,5),4:(3,4),5:(4,)}[stage]:branches[index]=None
        branches[7]=None
        return [2,'8',[stage],inverse(),[],None if stage==0 else branches,None,None,[1,[stage],evaluated({0:4,2:1,3:2,4:4,5:4}[stage])]]
    def floor_stop():
        value=stopped(0);value[3]=inverse('1/20','1/10');value[8][2]=evaluated(4,Fraction(-23,740),Fraction(7,370));return value
    def point_stop():
        comparison=evaluated(4)
        return [2,'8',[0],None,[point(floor=1,comparison=comparison)],None,None,None,[1,[0],copy.deepcopy(comparison)]]
    def refused():
        value=positive_delivered();value[2]=[6];value[6]=None;value[8]=[3,[6],exact(3,'1/2','3/4')];return value
    def grid_stop(selection=True,refusal=False):
        value=positive_delivered();value[2]=[6];value[6]=None
        value[3]=inverse('11/10','7/5');value[5][6]=rng('11/10','7/5')
        value[5][7]=rng('11/10','7/5') if selection else rng('111/100','112/100')
        if not selection:
            value[3]=inverse('111/100','112/100');value[5][6]=rng('111/100','112/100')
        value[8]=[3 if refusal else 1,[6],evaluated(1,1,2) if refusal else evaluated(1)]
        return value
    def bind_evidence(value):
        if not isinstance(value,list) or len(value)<9: return
        if value[6] is None:
            value[7]=None
        elif value[5] is not None and value[5][7] is not None:
            lower,upper=(fraction(endpoint[1]) for endpoint in value[5][7])
            selected=fraction(value[6][1]);lower-=selected;upper-=selected
            bound=(lower,upper) if lower>=0 else (-upper,-lower) if upper<=0 else (Fraction(0),max(-lower,upper))
            value[7]=rng(*bound)
        for check in value[4]:
            if check[2]==[1] and check[1][0]==0 and check[4][1][0]==0:
                old=copy.deepcopy(check[4]);wall=fraction(check[1][1][1])
                check[4][1][1]=int(0<wall<1)
                if len(value[8])==3 and value[8][1]==[0] and value[8][2]==old:
                    value[8][2]=copy.deepcopy(check[4])
    def row(name,value,result='valid',*,data=None,expected=None,edition='attempt',index=0,expected_index=None,proc=None,expected_proc=None,proof='valid',raw=None,rule=None,bind=True):
        data=copy.deepcopy(data or inputs())
        proc=copy.deepcopy(proc or procedure())
        if bind:
            if edition=='attempt': bind_evidence(value)
            else:
                for attempt in value[3]: bind_evidence(attempt)
        rows.append(dict(case=name,edition=edition,inputs=data,expected=copy.deepcopy(expected or data),procedure=proc,expected_procedure=copy.deepcopy(expected_proc or proc),index=index,expected_index=index if expected_index is None else expected_index,proof=proof,value=value,canonical=(encode(value) if raw is None else raw).hex(),result=result,rule=rule or name))
    def bad(name,factory,mutation,cause,**kwargs):
        value=factory();mutation(value);row(name,value,cause,**kwargs)
    positive=inputs(width='1')
    positive_grid=inputs(width='1',delivery='grid',maximum_error='1/4')
    ridge=inputs(floor=1)
    grid=inputs(width='1',previous='1',deadband='1/100',delivery='grid')
    row('delivered-zero',delivered())
    hold=inputs(previous='3/37')
    row('delivered-exact-hold',delivered(hold),data=hold)
    def symbolic_hold():
        value=positive_delivered();value[5][2]=evaluated(1,-2,-1)
        value[5][3]=value[5][4]=value[5][5]=None
        value[5][7]=rng('1/4','1/4');value[6]=source('1/4');return value
    row('delivered-symbolic-hold',symbolic_hold(),data=positive)
    absolute_clip=inputs(absolute_cap='1/10')
    row('delivered-absolute-clip',delivered(absolute_clip),data=absolute_clip)
    row('delivered-relative-clip',delivered())
    grid_delivered=inputs(previous='1',delivery='grid')
    row('delivered-grid-clip',delivered(grid_delivered),data=grid_delivered)
    ridge_hold=inputs(floor=1,deadband='9/10')
    def ridge_hold_value():
        value=delivered()
        value[5]=[True,None,evaluated(1,Fraction(1,40)-Fraction(17,233),Fraction(1,40)-Fraction(679,9321)),None,None,None,rng('679/9321','17/233'),rng('1/4','1/4')]
        value[6]=source('1/4');return value
    row('delivered-ridge-hold',ridge_hold_value(),data=ridge_hold)
    def positive_floor_failure(ridge_floor=False):
        value=ridge_hold_value() if ridge_floor else delivered(inputs(deadband='9/10'))
        value[3]=inverse('1/20','3/50');value[5][0]=False;value[5][1]=evaluated(4,-2,-1);return value
    row('delivered-positive-rational-floor-hold',positive_floor_failure(),data=inputs(width='1',deadband='9/10'))
    row('delivered-positive-ridge-floor-hold',positive_floor_failure(True),data=inputs(width='1',floor=1,deadband='9/10'))
    def failed_floor_stop(ridge_floor=False):
        value=positive_floor_failure(ridge_floor);value[5][2]=None;value[5][7]=None
        value[2]=[2];value[6]=None;value[8]=[1,[2],evaluated(1)];return value
    row('ridge-floor-failed-deadband-stop',failed_floor_stop(True),data=inputs(width='1',floor=1,deadband='9/10'))
    row('rational-floor-failed-evaluated-stop',failed_floor_stop(),'Comparison::ExactEvaluated',data=inputs(width='1',deadband='9/10'))
    def incomplete_floor_stop():
        value=point_stop();value[3]=inverse();value[5]=stopped(2)[5];return value
    row('floor-stop-incomplete-prefix',incomplete_floor_stop(),'IncompleteDecision',data=inputs(width='1',floor=1))
    row('delivered-positive',positive_delivered(),data=inputs(width='1',delivery='grid',maximum_error='1/4'))
    row('floor-target-straddle',floor_stop(),data=positive)
    row('floor-point-straddle',point_stop(),data=ridge)
    row('floor-point-missing-proof',point_stop(),'Comparison::MissingProof',data=ridge,proof='missing')
    for stage in (2,3,4,5):row(f'position-stop-{stage}',stopped(stage),data=positive)
    row('exact-representation-refused',refused(),data=positive)
    row('grid-selection-straddle',grid_stop(),data=grid)
    row('grid-error-straddle',grid_stop(False),data=grid)
    row('grid-error-refused',grid_stop(False,True),data=grid)
    no_grid=inputs(absolute_cap='1/10',delivery='grid',quantum='1',maximum_error='1')
    def empty_grid_delivery():
        value=delivered(no_grid);value[2]=[6];value[6]=None;value[8]=[3,[6],exact(1,2,1)];return value
    row('grid-no-admissible-point',empty_grid_delivery(),'Grid',data=no_grid)
    for stage in range(7):
        for cause in range(1,8):row(f'operational-{stage}-{cause}',operational(stage,cause))
    bad('edition',operational,lambda v:v.__setitem__(0,1),'Edition')
    bad('attempt-arity',operational,lambda v:v.append(None),'Arity')
    bad('stage-code',operational,lambda v:v.__setitem__(2,[7]),'Stage')
    bad('stage-arity',operational,lambda v:v.__setitem__(2,[1,0]),'Arity')
    bad('result-code',operational,lambda v:v.__setitem__(8,[4]),'Result')
    bad('operational-extra-verdict',operational,lambda v:v[8].append(2),'Arity')
    bad('delivered-extra-member',delivered,lambda v:v[8].append(0),'Arity')
    bad('result-stage-code',operational,lambda v:v[8].__setitem__(1,[7]),'Stage')
    bad('precision',operational,lambda v:v.__setitem__(1,'16'),'Precision')
    row('attempt-index',operational(), 'AttemptIndex',index=1,expected_index=0)
    row('undeclared-index',operational(),'AttemptIndex',index=3)
    wrong=procedure();wrong[5]=[0]
    row('precision-kind',operational(),'PrecisionKind',proc=wrong)
    for key,value,cause in [('width','bad','Number'),('width','-1','Width'),('previous','0','Previous')]:
        row('context-'+key+'-'+cause,operational(),cause,data=inputs(**{key:value}))
    for key,value in [('quantum','0'),('quantum','-1'),('maximum_error','1/100')]:
        row('grid-declaration-'+key+'-'+value.replace('/','-'),operational(),'DeliveryDeclaration',data=inputs(delivery='grid',**{key:value}))
    row('procedure-binding',operational(),'Procedure',expected_proc=procedure('foreign'))
    for name,key in [('floor','width'),('deadband','deadband'),('direction','previous'),('absolute','absolute_cap'),('relative','relative_cap'),('delivery','maximum_error')]:
        actual=inputs(delivery='grid') if name=='delivery' else inputs()
        changed=dict(actual,**{key:'2'})
        row('operand-binding-'+name,operational(),'Inputs',data=actual,expected=changed)
    def with_check():
        value=operational();value[4]=[point()];return value
    bad('floor-check-floor',with_check,lambda v:v[4][0].__setitem__(2,[1]),'FloorBinding')
    bad('floor-check-point',with_check,lambda v:v[4][0].__setitem__(1,[1,['clean-elasticity-ridge-v1','2*ln(2)',source(0),source(1)]]),'Point')
    bad('zero-width-flag',delivered,lambda v:v[5].__setitem__(0,False),'ZeroWidth')
    bad('zero-width-floor',delivered,lambda v:(v[5].__setitem__(1,evaluated(4,1,2)),v.__setitem__(3,inverse())),'ZeroFloor')
    bad('positive-missing-floor',positive_delivered,lambda v:v[5].__setitem__(1,None),'MissingFloor',data=positive_grid)
    bad('missing-target',positive_delivered,lambda v:v.__setitem__(3,None),'Target',data=positive_grid)
    for position,predicate in [(1,4),(2,1),(3,4),(4,4),(5,2)]:
        for key,mutate,cause in [('predicate',foreign_predicate,'Comparison::ExpectedPredicate'),('reduction',lambda c:c[1].__setitem__(1,1),'Comparison::ExpectedReduction'),('threshold',foreign_threshold,'Comparison::Threshold')]:
            bad(f'position-{position}-{key}',positive_delivered,lambda v,position=position,mutate=mutate:mutate(v[5][position]),cause,data=positive_grid)
        bad(f'position-{position}-operational',positive_delivered,lambda v,position=position:v[5].__setitem__(position,[2,[2,5]]),'BranchOperational',data=positive_grid)
        bad(f'position-{position}-indecisive',positive_delivered,lambda v,position=position,predicate=predicate:v[5].__setitem__(position,evaluated(predicate)),'BranchIndecisive',data=positive_grid)
        bad(f'position-{position}-exact-symbolic',positive_delivered,lambda v,position=position,predicate=predicate:v[5].__setitem__(position,exact(predicate,1,2)),'Comparison::ExactContext',data=positive_grid)
    for position,predicate in [(2,1),(3,4),(4,4),(5,2)]:
        bad(f'position-{position}-evaluated-exact',delivered,lambda v,position=position,predicate=predicate:v[5].__setitem__(position,evaluated(predicate)),'Comparison::ExactEvaluated')
        for side,cause in [(1,'Comparison::ExactLeft'),(3,'Comparison::ExactRight')]:
            bad(f'position-{position}-exact-operand-{side}',delivered,lambda v,position=position,side=side:foreign_exact_position(v,position,side),cause)
    bad('floor-point-rational',point_stop,lambda v:v.__setitem__(4,[]),'PointFloor')
    bad('floor-point-missing',point_stop,lambda v:v.__setitem__(4,[]),'LastFloor',data=ridge)
    bad('floor-point-equality',point_stop,lambda v:v[8][2][1].__setitem__(3,[q(-2),True,q(2),True]),'FloorEquality',data=ridge)
    bad('inverse-with-comparison',lambda:stopped(2),lambda v:(v.__setitem__(5,None),v.__setitem__(2,[1]),v[8].__setitem__(1,[1])),'InverseComparison',data=positive)
    bad('delivery-without-branches',refused,lambda v:v.__setitem__(5,None),'IncompleteDecision',data=positive)
    bad('delivery-range-reversed',refused,lambda v:v[5].__setitem__(7,rng(2,1)),'Range',data=positive)
    bad('indecisive-kind',lambda:stopped(2),lambda v:v[8].__setitem__(2,[2,[2,5]]),'IndecisiveKind',data=positive)
    bad('indecisive-verdict',lambda:stopped(2),lambda v:v[8].__setitem__(2,evaluated(1,1,2)),'IndecisiveVerdict',data=positive)
    bad('refusal-stage',lambda:stopped(2),lambda v:v.__setitem__(8,[3,[2],evaluated(1,1,2)]),'RefusalStage',data=positive)
    bad('refusal-kind',refused,lambda v:v[8].__setitem__(2,[2,[2,5]]),'RefusalKind',data=positive)
    bad('exact-delivery-evaluated',refused,lambda v:v[8].__setitem__(2,evaluated(3)),'Comparison::ExactEvaluated',data=positive)
    bad('exact-delivery-indecisive-exact',refused,lambda v:v[8].__setitem__(0,1),'IndecisiveKind',data=positive)
    bad('refusal-verdict',symbolic_hold,lambda v:(v.__setitem__(2,[6]),v.__setitem__(6,None),v.__setitem__(8,[3,[6],exact(3,'1/4','1/4')])),'RefusalVerdict',data=positive)
    for cause in (0,8):bad(f'cause-{cause}',operational,lambda v,cause=cause:v[8].__setitem__(2,cause),'Cause')
    bad('delivered-branches',delivered,lambda v:v.__setitem__(5,None),'IncompleteDecision')
    bad('delivered-value',delivered,lambda v:v.__setitem__(6,None),'DeliveredValue')
    bad('delivered-stop',delivered,lambda v:v.__setitem__(2,[6]),'DeliveredStop')
    bad('missing-stop',operational,lambda v:v.__setitem__(2,None),'MissingStop')
    bad('stop-stage',operational,lambda v:v.__setitem__(2,[2]),'StopStage')
    bad('stopped-value',operational,lambda v:v.__setitem__(6,source(1)),'StoppedValue')
    bad('order-context-floor-check',with_check,lambda v:v[4][0].__setitem__(2,[1]),'Inputs',expected=inputs(width='2'),rule='outer input binding before floor-check binding')
    bad('order-floor-check-branches',positive_delivered,lambda v:(v.__setitem__(4,[point(floor=1)]),v[5].__setitem__(0,True)),'FloorBinding',data=positive_grid,rule='floor check before branch width')
    bad('order-floor-point-binding-kind',with_check,lambda v:(v[4][0].__setitem__(2,[1]),v[4][0].__setitem__(1,[1,['clean-elasticity-ridge-v1','2*ln(2)',source(0),source(1)]])),'FloorBinding',rule='floor binding before point kind')
    bad('instance-floor-verdict-binding',with_check,lambda v:(v[4][0][4][1].__setitem__(5,1),v[4].append(point(floor=1))),'Comparison::VerdictAgreement',rule='earlier point verdict before later point floor binding')
    for name,first,second,cause in [
        ('edition-arity',lambda v:v.__setitem__(0,1),lambda v:v.append(0),'Edition'),
        ('cause-missing-stop',lambda v:v[8].__setitem__(2,8),lambda v:v.__setitem__(2,None),'Cause'),
        ('precision-cause',lambda v:v.__setitem__(1,'16'),lambda v:v[8].__setitem__(2,8),'Precision'),
        ('missing-stop-value',lambda v:v.__setitem__(2,None),lambda v:v.__setitem__(6,source(1)),'MissingStop'),
        ('stage-value',lambda v:v.__setitem__(2,[2]),lambda v:v.__setitem__(6,source(1)),'StopStage'),
    ]:bad('order-'+name,operational,lambda v,first=first,second=second:(first(v),second(v)),cause,rule='overlap '+name)
    bad('order-zero-flag-floor',delivered,lambda v:(v[5].__setitem__(0,False),v[5].__setitem__(1,evaluated(4,1,2)),v.__setitem__(3,inverse())),'ZeroWidth',rule='overlap zero-width agreement then floor presence')
    bad('order-delivered-value-stop',delivered,lambda v:(v.__setitem__(6,None),v.__setitem__(2,[6])),'DeliveredValue',rule='overlap delivered value then stopped-at')
    bad('order-branch-result',positive_delivered,lambda v:(foreign_predicate(v[5][2]),v.__setitem__(8,[2,[6],8]),v.__setitem__(2,[6]),v.__setitem__(6,None)),'Comparison::ExpectedPredicate',data=positive,rule='overlap branch then result')
    bad('instance-branch-verdict-predicate',positive_delivered,lambda v:(v[5][2][1].__setitem__(6,0),v[5][3][1].__setitem__(2,5)),'Comparison::VerdictAgreement',data=positive_grid,rule='earlier branch verdict before later branch predicate')
    for constructor in (1,3):
        bad(f'result-{constructor}-extra',refused,lambda v,constructor=constructor:(v[8].__setitem__(0,constructor),v[8].append(0)),'Arity',data=positive)
    for code in range(4):
        bad(f'relation-{code}-agreement',lambda:stopped(2),lambda v,code=code:(v[8][2].__setitem__(1,evaluated(1,1,2)[1] if code==3 else evaluated(1)[1]),v[8][2][1].__setitem__(5,code)),'Comparison::RelationAgreement',data=positive)

    bad('prefix-empty',lambda:operational(2),lambda v:v.__setitem__(5,[True,None,None,None,None,None,rng('3/37','3/37'),None]),'EmptyPrefix')
    bad('prefix-gap-direction',positive_delivered,lambda v:v[5].__setitem__(2,None),'BrokenPrefix',data=positive_grid)
    bad('prefix-gap-absolute',positive_delivered,lambda v:v[5].__setitem__(5,None),'BrokenPrefix',data=positive_grid)
    bad('prefix-gap-relative',positive_delivered,lambda v:v[5].__setitem__(3,None),'BrokenPrefix',data=positive_grid)
    for field in (3,4,5):
        bad(f'hold-past-end-{field}',symbolic_hold,lambda v,field=field:v[5].__setitem__(field,evaluated(2 if field==5 else 4,1,2)),'PastEnd',data=positive)
    bad('prefix-early-ideal',lambda:stopped(2),lambda v:v[5].__setitem__(7,rng('1/2','3/4')),'EarlyIdeal',data=positive)
    bad('complete-missing-ideal',symbolic_hold,lambda v:v[5].__setitem__(7,None),'MissingIdeal',data=positive)
    bad('proposal-range-substitution',positive_delivered,lambda v:(v[5].__setitem__(6,rng('2/3','3/4')),v[5].__setitem__(7,rng('2/3','3/4'))),'ProposalRange',data=positive_grid)
    bad('ideal-range-substitution',positive_delivered,lambda v:v[5].__setitem__(7,rng('2/3','3/4')),'IdealRange',data=positive_grid)
    bad('hold-ideal-substitution',symbolic_hold,lambda v:v[5].__setitem__(7,rng('1/4','1/3')),'IdealRange',data=positive_grid)
    bad('stop-missing-floor',lambda:stopped(2),lambda v:v.__setitem__(5,None),'MissingBeforeStop',data=positive)
    bad('stop-missing-direction',lambda:stopped(4),lambda v:v[5].__setitem__(5,None),'MissingBeforeStop',data=positive)
    bad('stop-present-direction',lambda:stopped(3),lambda v:v[5].__setitem__(5,evaluated(2,1,2)),'PresentAfterStop',data=positive)
    bad('stop-after-hold',symbolic_hold,lambda v:(v.__setitem__(2,[3]),v.__setitem__(6,None),v.__setitem__(8,[1,[3],evaluated(2)])),'StopAfterHold',data=positive)
    bad('hold-refusal-foreign-ideal',symbolic_hold,lambda v:(v[5].__setitem__(7,rng('1/4','1/3')),v.__setitem__(2,[6]),v.__setitem__(6,None),v.__setitem__(8,[3,[6],exact(3,'1/4','1/3')])),'IdealRange',data=positive)
    bad('hold-refusal-point',symbolic_hold,lambda v:(v.__setitem__(2,[6]),v.__setitem__(6,None),v.__setitem__(8,[3,[6],exact(3,'1/4','1/4')])),'RefusalVerdict',data=positive)
    bad('order-proposal-ideal',positive_delivered,lambda v:(v[5].__setitem__(6,rng('2/3','3/4')),v[5].__setitem__(7,None)),'ProposalRange',data=positive,rule='proposal binding before ideal presence')
    bad('order-ideal-result',symbolic_hold,lambda v:(v[5].__setitem__(7,rng('1/4','1/3')),v.__setitem__(8,[2,[6],8]),v.__setitem__(2,[6]),v.__setitem__(6,None)),'IdealRange',data=positive,rule='ideal binding before result cause')

    def cap_after_hold():
        value=symbolic_hold();value[2]=[4];value[6]=None;value[8]=[1,[4],evaluated(4)];return value
    row('cap-stop-after-hold',cap_after_hold(),'StopAfterHold',data=positive)
    def hold_floor_stop(positive_width):
        value=positive_floor_failure(True) if positive_width else ridge_hold_value()
        value[2]=[0];value[6]=None;value[7]=None
        comparison=evaluated(4);comparison[1][1]=1
        decided=evaluated(4,1,2);decided[1][1]=1
        value[4]=[point('1/4',1,decided),point('1/10',1,copy.deepcopy(decided)),point('729/10000',1,comparison)]
        value[8]=[1,[0],copy.deepcopy(comparison)]
        return value
    for positive_width in (True,False):
        row('hold-grid-walk-floor-stop-'+('positive' if positive_width else 'zero'),hold_floor_stop(positive_width),data=inputs(width='1' if positive_width else '0',floor=1,deadband='9/10',delivery='grid',quantum='1/10000',maximum_error='1/10000'))
    def new_error_row(name,mutation,cause,*,data=None,factory=None):
        data=data or grid_delivered
        value=(factory or (lambda:delivered(data)))();bind_evidence(value);mutation(value)
        row(name,value,cause,data=data,bind=False)
    new_error_row('delivered-without-error',lambda v:v.__setitem__(7,None),'DeliveredError')
    new_error_row('stop-with-error',lambda v:v.__setitem__(7,rng(0,0)),'StoppedError',data=positive,factory=lambda:stopped(2))
    new_error_row('delivered-wrong-error',lambda v:v[7].__setitem__(1,source('1/100')),'DeliveryErrorRange')
    def far_delivery(data):
        value=delivered(data);value[6]=source('2');return value
    for kind in ('grid','exact'):
        data=inputs(previous='1',delivery=kind)
        new_error_row('delivered-error-bound-'+kind,lambda v:None,'DeliveryErrorBound',data=data,factory=lambda data=data:far_delivery(data))
    for inside in (True,False):
        value=operational();comparison=evaluated(4,1,2);comparison[1][1]=0 if inside else 1
        value[4]=[point('1/4' if inside else '1',1,comparison)]
        row('floor-check-identity-inside' if inside else 'floor-check-derivative-outside',value,'Comparison::ExpectedReduction',data=ridge,bind=False)

    def record(attempts=None):return [2,procedure(),input_value(inputs()),attempts if attempts is not None else [operational()]]
    row('record-operational',record(),edition='record')
    row('record-delivered',record([delivered()]),edition='record')
    r=[2,procedure(),input_value(positive),[refused()]];row('record-refused',r,data=positive,edition='record')
    r=[2,procedure(),input_value(positive),[floor_stop()]];row('record-indecisive',r,data=positive,edition='record')
    r=record([operational(),operational(2)]);r[3][1][1]='16';row('record-two-attempts',r,edition='record')
    bad('record-empty',record,lambda v:v.__setitem__(3,[]),'Empty',edition='record')
    bad('record-summary',record,lambda v:v.append(2),'Arity',edition='record')
    bad('record-old-attempt',record,lambda v:v[3].__setitem__(0,operational()[1:8]),'Member',edition='record')
    bad('record-inputs',record,lambda v:v[2].__setitem__(5,source('1/3')),'Inputs',edition='record')
    bad('record-procedure',record,lambda v:v[1].__setitem__(2,'foreign'),'Procedure',edition='record')
    bad('order-record-procedure-inputs',record,lambda v:(v[1].__setitem__(2,'foreign'),v[2].__setitem__(5,source('1/3'))),'Procedure',edition='record',rule='procedure binding before input binding')
    bad('order-record-inputs-empty',record,lambda v:(v[2].__setitem__(5,source('1/3')),v.__setitem__(3,[])),'Inputs',edition='record',rule='input binding before nonempty attempts')
    bad('order-record-inputs-attempt',record,lambda v:(v[2].__setitem__(5,source('1/3')),v[3][0].__setitem__(2,None)),'Inputs',edition='record',rule='record input binding before nested attempt stop')
    bad('order-record-terminal-successor',lambda:record([delivered(),operational()]),lambda v:v[3][1].__setitem__(1,'24'),'Successor',edition='record',rule='terminal predecessor before successor precision')
    bad('record-successor',lambda:record([delivered(),operational()]),lambda v:v[3][1].__setitem__(1,'16'),'Successor',edition='record')
    r=[2,procedure(),input_value(positive),[refused(),operational()]];r[3][1][1]='16';row('record-refusal-successor',r,'Successor',data=positive,edition='record')
    r=record([operational(),operational()]);r[3][0][2]=None;r[3][1][1]='24';row('instance-attempt-stop-precision',r,'MissingStop',edition='record',rule='earlier attempt stop before later attempt precision')
    for raw,name in [(b'\x9f\xff','indefinite'),(b'\xc0'+encode(operational()),'tag'),(encode(operational())+b'\x00','trailing')]:
        row('framing-'+name,operational(),{'indefinite':'IndefiniteLength','tag':'Tag','trailing':'TrailingBytes'}[name],raw=raw)
    for value in rows:
        value['structural_only']=True
    rows=rows[::2][::-1]+rows[1::2]
    return dict(provenance='Fresh controller values; independent integer encoder and Fraction endpoint comparisons. No codec or interchange imports; no enclosure soundness, controller execution or publication claim.',distinct_inputs=len({json.dumps({k:v for k,v in row.items() if k not in ('case','rule','result','value')},sort_keys=True) for row in rows}),distinct_byte_inputs=len({row['canonical'] for row in rows}),cases=rows)


def check_controllers(path):
    expected=controller_vectors()
    if json.loads(Path(path).read_text())!=expected:
        raise ValueError('controller corpus differs from independent integer derivation')
    return expected


def check_comparisons(path):
    expected=comparison_vectors()
    if json.loads(Path(path).read_text()) != expected:
        raise ValueError('comparison corpus differs from independent integer derivation')
    return expected


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

    comparison_path = Path('packages/host/tests/data/comparison-carriers.json')
    if args.write:
        comparison_path.write_text(json.dumps(comparison_vectors(), indent=2) + '\n')
    comparison_result = check_comparisons(comparison_path)
    print(f"COMPARISON-VECTORS cases={len(comparison_result['cases'])} distinct={comparison_result['distinct_inputs']} byte_inputs={comparison_result['distinct_byte_inputs']} order=unsorted")

    controller_path = Path('packages/host/tests/data/controller-carriers.json')
    if args.write:
        controller_path.write_text(json.dumps(controller_vectors(), indent=2) + '\n')
    controller_result = check_controllers(controller_path)
    print(f"CONTROLLER-VECTORS cases={len(controller_result['cases'])} distinct={controller_result['distinct_inputs']} byte_inputs={controller_result['distinct_byte_inputs']} order=unsorted")
