"""Independent component encodings; no package codec or chain evaluator.

(´[ROOT-amend:identity:local-authority-boundary]´)
Semantic substitutions are expected future consumer results, not executed claims.
"""
import json
import sys
from pathlib import Path


def independent(value):
    """Copy each list occurrence, not its alias graph, before changing a position."""
    if isinstance(value, list):
        return [independent(item) for item in value]
    return value


def head(major, n):
    if not 0 <= n < 2**64:
        raise ValueError('unsigned range')
    if n < 24:
        return bytes([major * 32 + n])
    for width, additional in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 2**(width * 8):
            return bytes([major * 32 + additional]) + n.to_bytes(width, 'big')
    raise ValueError('unsigned range')


def canonical(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        return head(3, len(value.encode())) + value.encode()
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(canonical(v) for v in value)
    raise ValueError('closed fixture type')


def h(n):
    if not 0 <= n < 2**64:
        raise ValueError('unsigned range')
    return next(size for limit, size in ((24, 1), (256, 2), (65536, 3), (2**32, 5), (2**64, 9)) if n < limit)


def size(value):
    if value is None:
        return 1
    if isinstance(value, int):
        return h(value)
    if isinstance(value, (str, bytes)):
        n = len(value.encode()) if isinstance(value, str) else len(value)
        return h(n) + n
    return h(len(value)) + sum(size(v) for v in value)


def public(value):
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, list):
        return [public(v) for v in value]
    return value


def vectors():
    def ref(name, edition=1):
        return ['org.peer-network.test.fixture', name, edition]
    run = bytes(range(32))
    history = canonical(['fixture-history', 0])
    context = [run, history, 3]
    scope = [run, history, 0, 0]
    prior = [history, 0, 3]
    # These are public fixture parameters, not operational run selections.
    config = canonical([run, 'pn-host-bip340-v1/' + bytes([7]).hex()*32,
                        'pn-act-authentication/author-token-bip340/v2', 2,
                        [8, 4096, 64, 32, 16, 8192]])
    local_ref = ['org.peer-network.test.authority', 'author-token', 1]
    local = [1, local_ref, scope, [ref('signed-chain'), bytes([8])*32],
             ref('signed-validation'), ref('authorization'), ref('projection'), config]
    paper = [1, ref('provenance'), 0, scope, ref('second-party'), ref('rules'),
             ref('convention'), ref('projection'), [ref('published-data'), ref('destroyed-unit')]]
    author = independent(paper)
    author[1], author[2], author[8][1] = ref('author-case'), 1, None
    successor = independent(paper)
    successor[1], successor[3] = ref('provenance', 2), [run, history, 2, 3]
    actors = ['pn-devnet-v1/'+run.hex()+'/'+bytes([n]).hex()*32 for n in (11, 12)]
    # Opaque raw bytes selected by a synthetic evaluator premise. They are not
    # Elements blocks, and no linkage/consensus/signature truth is inferred.
    block_values = [[height, ['unrelated', height], ['fixture-event', height]] for height in range(5, 11)]
    blocks = [canonical(v) for v in block_values]
    account = [1, context, [8, bytes([9])*32, 2], [config, canonical(['fixture-chain-parameters'])], [5, blocks], prior]
    parts = [[1, actor, [issuance, 0, 0, bytes([i+1])*36], issuance, 8, prior]
             for i, (actor, issuance) in enumerate(zip(actors, (5, 7)))]
    associations = [[1, context, i, ['act', actors[i % 2], i, 'Registration'], local_ref, [context, 0], i % 2]
                    for i in range(3)]
    boundary = ['org.peer-network.test.publication.author-authority', 1, context, local, account, parts, associations]
    # Each base is a value tree: equal contexts and references are independent
    # occurrences, including across bases. Bytes, strings and integers are immutable.
    paper, author, successor, local, account, parts, associations, boundary = (
        independent(value) for value in
        (paper, author, successor, local, account, parts, associations, boundary))
    rows = []
    def row(name, family, value, expected='RepresentationEqual', premises=None):
        encoded = canonical(value)
        assert len(encoded) == size(value)
        rows.append(dict(name=name, family=family, value=public(value), encoded=encoded.hex(),
                         encoded_bytes=len(encoded), formula_bytes=size(value), expected=expected,
                         premises=premises or []))
    for name, family, value in (
        ('provenance', 'PaperCaseDeclaration', paper), ('author-case', 'PaperCaseDeclaration', author),
        ('empty-paper-set', 'PaperCaseBoundary', [1, context, [], []]),
        ('first-adoption', 'PaperCaseBoundary', [1, context, [paper], []]),
        ('unchanged', 'PaperCaseBoundary', [1, context, [paper], []]),
        ('successor', 'PaperCaseBoundary', [1, context, [successor], [[0, paper[1], successor[1]]]]),
        ('withdrawal', 'PaperCaseBoundary', [1, context, [], [[1, paper[1]]]]),
        ('local-declaration', 'LocalAuthorityDeclaration', local),
        ('shared-account', 'AuthorityAccount', account),
        ('local-boundary', 'LocalAuthorityBoundary', boundary)):
        row(name, family, value, premises=['independently selected descriptor/context and predecessor',
            'synthetic supported evaluator and public-data binding; consensus validity remains a premise'])
    empty_account = independent(account)
    empty_account[4] = [8, blocks[3:]]
    empty_boundary = independent(boundary)
    empty_boundary[4:7] = [empty_account, [], []]
    row('empty-domain-account', 'AuthorityAccount', empty_account)
    row('empty-domain-boundary', 'LocalAuthorityBoundary', empty_boundary)
    allowances = []
    for name, value in (('paper-declaration', paper), ('paper-boundary', [1, context, [], []]),
                        ('local-declaration', local), ('account', account), ('local-boundary', boundary)):
        n = size(value)
        assert len(canonical(value)) == n
        allowances += [dict(name=name+'-exact', encoded_bytes=n, allowance=n, expected='BudgetAvailable'),
                       dict(name=name+'-one-over', encoded_bytes=n, allowance=n-1, expected='UnavailableBudget')]
    chain_formula = h(2)+h(5)+h(6)+sum(h(len(b))+len(b) for b in blocks)
    account_formula = h(6)+h(1)+size(context)+size(account[2])+size(account[3])+chain_formula+size(prior)
    assert chain_formula == len(canonical(account[4])) and account_formula == len(canonical(account))
    scans = []
    for actor, issuance in zip(actors, (5, 7)):
        selected = blocks[issuance-5:8-5+1]
        scans.append(dict(actor=actor, issuance=issuance, first_height=5, scan_from=issuance, scan_through=8,
                          offsets=list(range(issuance-5, 8-5+1)), heights=list(range(issuance, 9)),
                          scan_blocks=9-issuance, scan_bytes=sum(map(len, selected)),
                          buffer_heights=[9, 10], buffer_enters_authority=False))
    substitutions = []
    def change(name, family, base, path, replacement, expected, assumptions='All earlier predicates pass'):
        value = independent(base)
        parent = value
        for index in path[:-1]:
            parent = parent[index]
        parent[path[-1]] = independent(replacement)
        row(name, family, value, expected, [assumptions])
    change('wrong-kind', 'PaperCaseDeclaration', paper, [2], 2, 'Kind')
    change('changed-body-same-ref', 'PaperCaseDeclaration', paper, [5], ref('different-rules'), 'DeclarationContent')
    change('wrong-history', 'PaperCaseDeclaration', paper, [3, 1], b'other', 'Context')
    both = independent(paper)
    both[2] = 2
    change('edition-before-kind', 'PaperCaseDeclaration', both, [0], 2, 'Edition')
    change('scope-not-in-force', 'PaperCaseDeclaration', paper, [3], [run, history, 2, 4], 'Scope', 'Authenticated declaration history includes this prospective descriptor, effective after current epoch three')
    for name, changes, expected in (
        ('omitted-withdrawal', [], 'Transition'),
        ('duplicate-withdrawal', [[1, paper[1]], [1, paper[1]]], 'Duplicate'),
        ('conflicting-change', [[0, paper[1], successor[1]], [1, paper[1]]], 'Duplicate'),
        ('spurious-change', [[1, ref('absent')]], 'Transition'),
        ('successor-not-active', [[0, paper[1], successor[1]]], 'Transition')):
        row(name, 'PaperCaseBoundary', [1, context, [], changes], expected, ['Predecessor has provenance; selected active set is empty'])
    change('declaration-rules-mismatch', 'LocalAuthorityDeclaration', local, [4], ref('other-rules'), 'Rules')
    change('declaration-convention-mismatch', 'LocalAuthorityDeclaration', local, [5], ref('other-convention'), 'Convention')
    change('declaration-ref-mismatch', 'LocalAuthorityDeclaration', local, [1, 2], 2, 'Declaration')
    change('declaration-run-mismatch', 'LocalAuthorityDeclaration', local, [7], config[:-1]+bytes([1]), 'Run', 'Both configurations use the same supported edition; candidate scan_bytes is 8193 instead of independently selected 8192')
    change('declaration-scope-mismatch', 'LocalAuthorityDeclaration', local, [2, 3], 4, 'Scope')
    both = independent(local)
    both[4] = ref('other-rules')
    change('declaration-before-rules', 'LocalAuthorityDeclaration', both, [1, 2], 2, 'Declaration')
    row('order-before-duplicate', 'PaperCaseBoundary', [1, context, [paper, author, author], []], 'Order', ['provenance sorts after author-case; repeated author-case also violates uniqueness'])
    row('descending-order', 'PaperCaseBoundary', [1, context, [paper, author], []], 'Order')
    change('omitted-last-block', 'AuthorityAccount', account, [4, 1], blocks[:-1], 'MissingEvidence')
    change('prefix-overflow', 'AuthorityAccount', account, [2, 0], 2**64-1, 'Overflow', 'Independently selected h equals candidate h; b=2')
    change('wrong-first-height', 'AuthorityAccount', account, [4, 0], 4, 'MissingEvidence', 'Six carried blocks do not cover 4..10')
    change('wrong-claimed-minimum', 'AuthorityAccount', account, [4], [6, blocks[1:]], 'MissingEvidence', 'Own interval count covers 6..10; independently established qualified issuance at 5 requires the omitted block; all earlier checks pass')
    change('superfluous-first-height', 'AuthorityAccount', account, [4], [4, [canonical([4, ["unrelated", 4], ["fixture-event", 4]])]+blocks], 'Coverage', 'All blocks 4..10 are valid and bound; required minimum is 5, no required evidence is missing')
    both = independent(account)
    both[2][0] = 2**64-1
    row('prefix-before-overflow', 'AuthorityAccount', both, 'Prefix', ['Independent h remains 8; candidate h also overflows with b=2'])
    change('too-late-scan', 'LocalAuthorityBoundary', boundary, [5, 0, 3], 6, 'Coverage')
    change('too-early-scan', 'LocalAuthorityBoundary', boundary, [5, 1, 3], 5, 'Coverage')
    change('buffer-scan', 'LocalAuthorityBoundary', boundary, [5, 0, 4], 10, 'Coverage')
    change('wrong-part', 'LocalAuthorityBoundary', boundary, [6, 0, 6], 1, 'Part')
    change('out-of-range-part', 'LocalAuthorityBoundary', boundary, [6, 0, 6], 2, 'Reference')
    change('transplanted-account', 'LocalAuthorityBoundary', boundary, [6, 0, 5, 0, 2], 4, 'Account')
    change('old-act-associated', 'LocalAuthorityBoundary', boundary, [6], associations+[[1, context, 3, ['act', actors[0], 99, 'Registration'], local_ref, [context, 0], 0]], 'Coverage', 'Exactly three new acts; the additional identity belongs to a historical epoch')
    change('wrong-discriminator', 'LocalAuthorityBoundary', boundary, [0], 'other-component', 'Shape')
    # A monotone but incorrect final position leaves Order satisfied.
    change('wrong-act-position', 'LocalAuthorityBoundary', boundary, [6, 2, 2], 4, 'Act', 'Exactly three new acts at positions 0,1,2; retained lookup by Context and ActId passes')
    both = independent(boundary)
    both[6][0][6] = 9
    both[6].append([1, context, 3, ['act', actors[0], 99, 'Registration'], local_ref, [context, 0], 0])
    row('coverage-before-reference', 'LocalAuthorityBoundary', both, 'Coverage', ['Roster expects three acts; four associations are strictly ordered; first part index is also out of range'])
    # These rows specify evaluator/input substitutions rather than pretend that
    # this independent framing program implements the future authority verifier.
    roster = [
        ('missing-paper-component', 'PaperCaseBoundary', 'required component absent; not []', 'MissingComponent'),
        ('unknown-selected-edition', 'PaperCaseDeclaration', 'caller selects an unsupported edition', 'UnsupportedEdition'),
        ('no-context', 'LocalAuthorityBoundary', 'no independently selected required_boundary_context', 'UnavailableContext'),
        ('annotation-only', 'LocalAuthorityBoundary', 'required core member absent; same name only in annotation', 'MissingComponent'),
        ('no-evaluator', 'AuthorityAccount', 'selected signed-chain rules have no supported evaluator', 'UnavailableRules'),
        ('unbound-account', 'AuthorityAccount', 'no independent binding established', 'UnavailableBinding'),
        ('bad-binding', 'AuthorityAccount', 'independent binding comparison demonstrably false', 'Binding'),
        ('bad-link', 'AuthorityAccount', 'selected evaluator demonstrates broken header linkage', 'Chain'),
        ('bad-transaction-commitment', 'AuthorityAccount', 'selected evaluator demonstrates incorrect transaction commitment', 'Chain'),
        ('bad-signed-evidence', 'AuthorityAccount', 'selected evaluator demonstrates invalid signed-chain evidence', 'Chain'),
        ('missing-acquisition', 'AuthorityAccount', 'reader cannot obtain identified complete record', 'UnavailableEvaluation'),
        ('missing-prior-epoch', 'AuthorityAccount', 'supplied record demonstrably omits required earlier epoch', 'MissingEvidence'),
        ('present-wrong-prior-context', 'AuthorityAccount', 'required prior epoch is present and binding passes, but its context does not match the selected history', 'History'),
        ('late-missing-act-evidence', 'AuthorityAccount', 'token scan demonstrates omission of required carried act evidence after earlier stages passed', 'MissingEvidence'),
        ('late-missing-retirement-placement', 'AuthorityAccount', 'original-epoch evaluation demonstrates omitted required retirement placement', 'MissingEvidence'),
        ('unknown-paper-evaluator', 'PaperCaseBoundary', 'all kinds and descriptors well-formed; selected proof evaluator is unavailable', 'UnavailableEvaluation'),
        ('prior-not-obtainable', 'AuthorityAccount', 'identified prior record cannot be acquired', 'UnavailableBinding'),
        ('later-spend-omitted', 'AuthorityAccount', 'full transaction scan finds a later spend absent from asserted token path', 'Path'),
        ('wrong-issuance-input', 'LocalAuthorityBoundary', 'qualified issuance input does not derive claimed Actor', 'Actor'),
        ('malformed-pnak-neighbor', 'LocalAuthorityBoundary', 'unrelated malformed output; token declaration remains valid', 'LocalAuthorized'),
        ('duplicate-keys', 'LocalAuthorityBoundary', 'declaration repeats a key; membership is a set', 'LocalAuthorized'),
        ('no-key-transfer', 'LocalAuthorityBoundary', 'valid transfer carries no new declaration; existing history remains', 'LocalAuthorized'),
        ('unsupported-token-path', 'LocalAuthorityBoundary', 'one token path unsupported; other part independently evaluable', 'LocalUnavailable'),
        ('empty-active-set', 'LocalAuthorityBoundary', 'complete valid scan gives empty H for covered Actor', 'ActorBinding'),
        ('outside-covered-domain', 'LocalAuthorityBoundary', 'requested Actor absent from covered part domain', 'NotCovered'),
        ('same-key-actor-swap', 'LocalAuthorityBoundary', 'valid key shared by two Actors; association selects wrong Actor', 'Actor'),
        ('changed-proposal', 'LocalAuthorityBoundary', 'retained V no longer matches admitted P comparison', 'RetainedActRefusal'),
        ('bad-signature', 'LocalAuthorityBoundary', 'complete account authorizes key but proposal signature invalid', 'Signature'),
        ('bad-approval', 'LocalAuthorityBoundary', 'approval for another exact V or seal', 'Signature'),
        ('wrong-material', 'LocalAuthorityBoundary', 'major-two material supplied for major-three V', 'RetainedActRefusal'),
        ('valid-signature-unauthorized', 'LocalAuthorityBoundary', 'valid role signature but complete H excludes signer', 'ActorBinding'),
        ('retirement-same-epoch', 'LocalAuthorityBoundary', 'retirement act in k; every act of k uses starting H', 'StartingSetUnchanged'),
        ('retirement-next-epoch', 'LocalAuthorityBoundary', 'valid retirement of k changes lower bound at k+1', 'NextEpochRetirement'),
        ('earlier-maximum', 'LocalAuthorityBoundary', 'earlier effective retirement dominates a smaller later point', 'MaximumRetained'),
        ('no-effect-point', 'LocalAuthorityBoundary', 'point not in original epoch history; later chain contains it', 'NeverActivated'),
        ('boundary-declaration', 'LocalAuthorityBoundary', 'valid declaration in retirement transaction itself', 'Included'),
        ('redeclaration', 'LocalAuthorityBoundary', 'key declared again after effective retirement', 'MembershipRestored'),
        ('current-chain-differs', 'LocalAuthorityBoundary', 'separate current account differs from retained at-pin account', 'HistoricalResultUnchanged'),
        ('settled-prefix-replaced', 'LocalAuthorityBoundary', 'previously settled prefix replaced', 'RunHalt'),
        ('no-courtesy', 'LocalAuthorityBoundary', 'no D, receipt, holder fact or opening supplied', 'LocalResultUnchanged'),
    ]
    for name, family, mutation, expected in roster:
        substitutions.append(dict(name=name, family=family, substitution=mutation, expected=expected,
                                  premise='All earlier predicates pass; independent evaluator supplies stated facts'))
    byte_mutations = []
    for name, family, value in (('paper', 'PaperCaseDeclaration', paper),
                                ('paper-boundary', 'PaperCaseBoundary', [1, context, [], []]),
                                ('local', 'LocalAuthorityDeclaration', local),
                                ('account', 'AuthorityAccount', account),
                                ('boundary', 'LocalAuthorityBoundary', boundary)):
        encoded = canonical(value)
        for suffix, changed in (('trailing', encoded+b'\x00'),
                                ('nonminimal-head', b'\x98'+bytes([len(value)])+encoded[1:])):
            byte_mutations.append(dict(name=name+'-'+suffix, family=family, encoded=changed.hex(),
                                       expected='Canonical', premise='Caller supports edition; complete allowance available'))
        byte_mutations.append(dict(name=name+'-budget-before-canonical', family=family,
                                   encoded=(encoded+b'\x00').hex(), allowance=len(encoded), expected='UnavailableBudget'))
    return dict(schema=1, classes=['PaperCaseDeclaration', 'PaperCaseBoundary', 'LocalAuthorityDeclaration', 'AuthorityAccount', 'LocalAuthorityBoundary'],
                scope='Representation and future-result fixtures only; synthetic evaluator, no consensus or authenticity claim',
                rows=rows, allowances=allowances, account_formula=dict(chain=chain_formula, account=account_formula),
                block_inputs=block_values, scans=scans, byte_mutations=byte_mutations, run_limit_cases=[dict(limit=limit, measured=measured, ceiling=ceiling,
                    expected='Available' if measured <= ceiling else 'LocalUnavailable')
                    for limit, measured in (('declaration_outputs', 2), ('history_bytes', 100),
                    ('history_transactions', 3), ('active_entries', 2), ('scan_blocks', scans[0]['scan_blocks']),
                    ('scan_bytes', scans[0]['scan_bytes'])) for ceiling in (measured, measured-1)],
                expected_future_substitutions=substitutions)


if __name__ == '__main__':
    value = vectors()
    if len(sys.argv) == 3 and sys.argv[1] == '--write':
        Path(sys.argv[2]).write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')
        outcome = 'written=true'
    elif len(sys.argv) == 1:
        assert json.load(sys.stdin) == value, 'independent boundary component vectors differ'
        outcome = 'equal=true'
    else:
        raise SystemExit('use --write PATH or supply the fixture on stdin')
    print('BOUNDARY-VECTORS classes=5 encoded='+str(len(value['rows']))+' allowances='+str(len(value['allowances']))+' substitutions='+str(len(value['expected_future_substitutions']))+' '+outcome)
