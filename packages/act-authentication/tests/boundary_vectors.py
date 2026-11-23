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
        return head(0, value) if value >= 0 else head(1, -1-value)
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
        return h(value if value >= 0 else -1-value)
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
    # Executable descriptors supplement the admitted rows. They retain the
    # independently encoded bytes and the selection/evaluator facts separately;
    # a Rust site names its own expected id set instead of deriving it here.
    site_by_family = {
        'PaperCaseDeclaration': 'paper_declaration',
        'PaperCaseBoundary': 'paper_boundary',
        'LocalAuthorityDeclaration': 'local_declaration',
        'AuthorityAccount': 'account',
        'LocalAuthorityBoundary': 'local_boundary',
    }
    executable = []
    for item in rows:
        site = site_by_family[item['family']]
        site += '_values' if item['expected'] == 'RepresentationEqual' else '_order'
        executable.append(dict(id='row:'+item['name'], site=site,
                               encoded=item['encoded'], expected=item['expected'],
                               selected_context=public(context), premise='synthetic selected evaluator'))
    for item in byte_mutations:
        site = site_by_family[item['family']]+'_order'
        executable.append(dict(id='byte:'+item['name'], site=site,
                               encoded=item['encoded'], expected=item['expected'],
                               allowance=item.get('allowance'), selected_context=public(context), premise=item.get('premise')))
    for item in allowances:
        family_key = item['name'].removesuffix('-exact').removesuffix('-one-over')
        family = {'paper-declaration':'PaperCaseDeclaration', 'paper-boundary':'PaperCaseBoundary',
                  'local-declaration':'LocalAuthorityDeclaration', 'account':'AuthorityAccount',
                  'local-boundary':'LocalAuthorityBoundary'}[family_key]
        base = {'PaperCaseDeclaration':paper, 'PaperCaseBoundary':[1,context,[],[]],
                'LocalAuthorityDeclaration':local, 'AuthorityAccount':account,
                'LocalAuthorityBoundary':boundary}[family]
        executable.append(dict(id='allowance:'+item['name'], site=site_by_family[family]+'_order',
                               encoded=canonical(base).hex(), allowance=item['allowance'],
                               expected=item['expected'], selected_context=public(context)))
    substitution_sites = {
        'missing-paper-component':'paper_boundary_order', 'unknown-selected-edition':'paper_declaration_order',
        'no-context':'local_boundary_order', 'annotation-only':'local_boundary_order',
        'no-evaluator':'account_order', 'unbound-account':'account_order',
        'bad-binding':'account_order', 'bad-link':'account_order',
        'bad-transaction-commitment':'account_order', 'bad-signed-evidence':'account_order',
        'missing-acquisition':'account_order', 'missing-prior-epoch':'account_order',
        'present-wrong-prior-context':'account_order', 'unknown-paper-evaluator':'paper_boundary_order',
        'prior-not-obtainable':'account_order', 'empty-active-set':'local_boundary_order',
        'outside-covered-domain':'local_boundary_order', 'same-key-actor-swap':'local_boundary_order',
        'changed-proposal':'local_boundary_order', 'bad-signature':'local_boundary_order',
        'bad-approval':'local_boundary_order', 'wrong-material':'local_boundary_order',
        'valid-signature-unauthorized':'local_boundary_order', 'no-courtesy':'missing_authority_case',
    }
    base_by_family = {'PaperCaseDeclaration':paper, 'PaperCaseBoundary':[1,context,[],[]],
                      'LocalAuthorityDeclaration':local, 'AuthorityAccount':account,
                      'LocalAuthorityBoundary':boundary}
    for item in substitutions:
        if item['name'] not in substitution_sites:
            continue  # This cut's scan-dependent descriptors belong to commit two.
        operand = [1, context, [paper], []] if item['name'] == 'unknown-paper-evaluator' else base_by_family[item['family']]
        executable.append(dict(id='substitution:'+item['name'], site=substitution_sites[item['name']],
                               encoded=canonical(operand).hex(),
                               expected=item['expected'], selected_context=public(context),
                               evaluator_outcome=item['name'], premise=item['premise']))
    def new_operand(family, name, value, expected, *, scenario=None, account_allowance=None,
                    history_scope_allowance=None, blocks_allowance=None):
        item = dict(id='new:'+name, site=site_by_family[family]+'_order',
                    encoded=canonical(value).hex(), expected=expected,
                    selected_context=public(context), scenario=scenario,
                    premise='synthetic selected evaluator')
        if account_allowance is not None:
            item['account_allowance'] = account_allowance
        if history_scope_allowance is not None:
            item['history_scope_allowance'] = history_scope_allowance
        if blocks_allowance is not None:
            item['blocks_allowance'] = blocks_allowance
        executable.append(item)
    structural = (
        ('PaperCaseDeclaration', 'paper_declaration', paper, 0,
         ('scope.run', [3,0], run[:-1]), ('reference.edition', [1,2], -1),
         ('reference.namespace', [1,0], '')),
        ('PaperCaseBoundary', 'paper_boundary', [1, context, [paper], []], 0,
         ('Context.run', [1,0], run[:-1]), ('active[0].reference.edition', [2,0,1,2], -1),
         ('active[0].reference.namespace', [2,0,1,0], '')),
        ('LocalAuthorityDeclaration', 'local_declaration', local, 0,
         ('second_party.genesis_hash', [3,1], bytes([8])*31), ('reference.edition', [1,2], -1),
         ('reference.namespace', [1,0], '')),
        ('AuthorityAccount', 'account', account, 0,
         ('pin.block_hash', [2,1], bytes([9])*31), ('prior.first_epoch', [5,1], 1),
         ('Context.history_scope', [1,1], b'')),
        ('LocalAuthorityBoundary', 'local_boundary', boundary, 1,
         ('Context.run', [2,0], run[:-1]), ('account.prior.first_epoch', [4,5,1], 1),
         ('declaration.reference.namespace', [3,1,0], '')),
    )
    for family, prefix, base, edition_at, length, range_case, field in structural:
        item = independent(base)
        item[edition_at] = b'1'
        new_operand(family, prefix+'-mistyped-edition', item, 'Shape')
        new_operand(family, prefix+'-missing-member', independent(base[:-1]), 'Shape')
        new_operand(family, prefix+'-extra-member', independent(base)+[0], 'Shape')
        for suffix, (member, path, replacement), expected in (
                ('member-length', length, 'Shape'),
                ('member-range', range_case, 'Shape'),
                ('nested-field', field, 'Field')):
            if family == 'AuthorityAccount' and suffix == 'nested-field':
                continue  # the typed Context.history_scope member owns this operand
            item = independent(base)
            parent = item
            for index in path[:-1]:
                parent = parent[index]
            parent[path[-1]] = replacement
            new_operand(family, prefix+'-'+suffix+':'+member, item, expected)
    def variant(base, path, replacement):
        item = independent(base)
        parent = item
        for index in path[:-1]:
            parent = parent[index]
        parent[path[-1]] = replacement
        return item
    # Earlier semantic faults cannot hide a later malformed member in the same
    # selected component. Each operand combines faults in distinct stages.
    overlaps = (
        ('PaperCaseDeclaration', 'paper_declaration', paper, [0], [1,0], [3,0]),
        ('LocalAuthorityDeclaration', 'local_declaration', local, [0], [1,0], [2,0]),
        ('AuthorityAccount', 'account', account, [0], [1,1], [2,1]),
        ('PaperCaseBoundary', 'paper_boundary', [1,context,[paper],[]], [0], [1,1], [2,0,3,0]),
        ('LocalAuthorityBoundary', 'local_boundary', boundary, [1], [2,1], [4,2,1]),
    )
    for family, prefix, base, edition_path, early_field, late_shape in overlaps:
        first = variant(base, edition_path, 2)
        new_operand(family, prefix+'-shape-before-edition', variant(first, late_shape, run[:-1]), 'Shape')
        first = variant(base, early_field, b'' if family in {'AuthorityAccount', 'PaperCaseBoundary', 'LocalAuthorityBoundary'} else '')
        new_operand(family, prefix+'-shape-before-field', variant(first, late_shape, run[:-1]), 'Shape')
    new_operand('PaperCaseDeclaration', 'paper_declaration-kind-zero-null-unit',
                variant(paper, [8, 1], None), 'Shape')
    new_operand('PaperCaseDeclaration', 'paper_declaration-kind-one-ref-unit',
                variant(paper, [2], 1), 'Shape')
    new_operand('LocalAuthorityBoundary', 'local_boundary-part-layout',
                variant(boundary, [5, 0, 0], 2), 'Shape')
    new_operand('LocalAuthorityBoundary', 'local_boundary-association-layout',
                variant(boundary, [6, 0, 0], 2), 'Shape')
    new_operand('PaperCaseBoundary', 'paper_boundary-nested-edition',
                variant([1, context, [paper], []], [2, 0, 0], 2), 'Field(Edition)')
    new_operand('PaperCaseBoundary', 'paper_boundary-nested-kind',
                variant([1, context, [paper], []], [2, 0, 2], 2), 'Field(Kind)')
    nested_history = b'nested-history-over-allowance-1234'
    new_operand('PaperCaseBoundary', 'paper_boundary-nested-history-budget',
                variant([1, context, [paper], []], [2, 0, 3, 1], nested_history),
                'UnavailableBudget', history_scope_allowance=len(nested_history)-1)
    new_operand('LocalAuthorityBoundary', 'local_boundary-nested-declaration-edition',
                variant(boundary, [3, 0], 2), 'Field(Edition)')
    new_operand('LocalAuthorityBoundary', 'local_boundary-nested-account-edition',
                variant(boundary, [4, 0], 2), 'Field(Edition)')
    new_operand('LocalAuthorityBoundary', 'local_boundary-nested-account-blocks-budget',
                boundary, 'UnavailableBudget', blocks_allowance=len(account[4][1])-1)
    noncanonical_account = next(item for item in executable if item['id'] == 'byte:account-nonminimal-head')
    executable.append(dict(id='new:account-own-budget-before-canonical', site='account_order',
                           encoded=noncanonical_account['encoded'],
                           account_allowance=len(bytes.fromhex(noncanonical_account['encoded']))-1,
                           expected='UnavailableBudget', selected_context=public(context)))
    new_operand('LocalAuthorityBoundary', 'local_boundary-account-allowance', boundary,
                'UnavailableBudget', account_allowance=len(canonical(account))-1)
    # Expand the admitted scalar and nested member paths, not a sample chosen
    # from the bytes produced by the Rust implementation.
    existing_ids = {item['id'] for item in executable}
    def typed_member(family, prefix, base, category, member, path, replacement, expected):
        member = member.lstrip('.')
        name = 'new:'+prefix+'-'+category+':'+member
        if name in existing_ids:
            return
        item = independent(base)
        parent = item
        for index in path[:-1]:
            parent = parent[index]
        parent[path[-1]] = replacement
        new_operand(family, prefix+'-'+category+':'+member, item, expected)
        existing_ids.add(name)
    def ref_members(family, prefix, base, member, path):
        for field, offset in (('namespace',0),('name',1)):
            typed_member(family,prefix,base,'member-length',member+'.'+field,path+[offset], 'a'*256,'Field')
            typed_member(family,prefix,base,'nested-field',member+'.'+field,path+[offset], '', 'Field')
        typed_member(family,prefix,base,'member-range',member+'.edition',path+[2],-1,'Shape')
    def common_context(family,prefix,base,member,path):
        typed_member(family,prefix,base,'member-length',member+'.run',path+[0],run[:-1],'Shape')
        typed_member(family,prefix,base,'member-length',member+'.history_scope',path+[1],b'','Field')
        typed_member(family,prefix,base,'member-range',member+'.epoch',path+[2],-1,'Shape')
        typed_member(family,prefix,base,'nested-field',member,path,[],'Shape')
    def common_scope(family,prefix,base,member,path):
        typed_member(family,prefix,base,'member-length',member+'.run',path+[0],run[:-1],'Shape')
        typed_member(family,prefix,base,'member-length',member+'.history_scope',path+[1],b'','Field')
        for field,offset in (('announced_at',2),('effective_at',3)):
            typed_member(family,prefix,base,'member-range',member+'.'+field,path+[offset],-1,'Shape')
        typed_member(family,prefix,base,'nested-field',member,path,[],'Shape')
    def paper_members(family,prefix,base,label,path):
        typed_member(family,prefix,base,'member-range',label+'.kind',path+[2],-1,'Shape')
        for field,offset in (('reference',1),('second_party',4),('rules',5),('convention',6),('projection',7),('data_selection.rule',8)):
            ref_path=path+[offset]+([0] if offset==8 else [])
            ref_members(family,prefix,base,label+'.'+field,ref_path)
        ref_members(family,prefix,base,label+'.data_selection.unit',path+[8,1])
        common_scope(family,prefix,base,label+'.scope',path+[3])
        typed_member(family,prefix,base,'nested-field',label+'.data_selection',path+[8],[],'Shape')
    def local_members(family,prefix,base,label,path):
        for field,offset in (('reference',1),('rules',4),('convention',5),('projection',6)):
            ref_members(family,prefix,base,label+'.'+field,path+[offset])
        ref_members(family,prefix,base,label+'.second_party.reference',path+[3,0])
        typed_member(family,prefix,base,'member-length',label+'.second_party.genesis_hash',path+[3,1],bytes([8])*31,'Shape')
        typed_member(family,prefix,base,'member-length',label+'.run_configuration',path+[7],b'','Field')
        common_scope(family,prefix,base,label+'.scope',path+[2])
        typed_member(family,prefix,base,'nested-field',label+'.second_party',path+[3],[],'Shape')
    def account_members(family,prefix,base,label,path):
        common_context(family,prefix,base,label+'.Context',path+[1])
        typed_member(family,prefix,base,'member-length',label+'.pin.block_hash',path+[2,1],bytes([9])*31,'Shape')
        for field,offset in (('height',0),('buffer',2)):
            typed_member(family,prefix,base,'member-range',label+'.pin.'+field,path+[2,offset],-1,'Shape')
        typed_member(family,prefix,base,'nested-field',label+'.pin',path+[2],[],'Shape')
        typed_member(family,prefix,base,'nested-field',label+'.run_evidence',path+[3],[],'Shape')
        typed_member(family,prefix,base,'member-range',label+'.chain_evidence.first_height',path+[4,0],-1,'Shape')
        typed_member(family,prefix,base,'nested-field',label+'.chain_evidence',path+[4],[],'Shape')
        typed_member(family,prefix,base,'nested-field',label+'.chain_evidence.blocks[0]',path+[4,1,0],0,'Shape')
        typed_member(family,prefix,base,'member-length',label+'.prior.history_scope',path+[5,0],b'','Field')
        typed_member(family,prefix,base,'member-range',label+'.prior.first_epoch',path+[5,1],1,'Shape')
        typed_member(family,prefix,base,'member-range',label+'.prior.exclusive_end',path+[5,2],-1,'Shape')
        typed_member(family,prefix,base,'nested-field',label+'.prior',path+[5],[],'Shape')
    paper_members('PaperCaseDeclaration','paper_declaration',paper,'',[])
    local_members('LocalAuthorityDeclaration','local_declaration',local,'',[])
    account_members('AuthorityAccount','account',account,'',[])
    paper_active = [1,context,[paper],[]]
    common_context('PaperCaseBoundary','paper_boundary',paper_active,'Context',[1])
    paper_members('PaperCaseBoundary','paper_boundary',paper_active,'active[0]',[2,0])
    typed_member('PaperCaseBoundary','paper_boundary',paper_active,'nested-field','active[0]',[2,0],[],'Shape')
    paper_successor = [1,context,[successor],[[0,paper[1],successor[1]]]]
    for label,path in (('changes[0].old',[3,0,1]),('changes[0].new',[3,0,2])):
        ref_members('PaperCaseBoundary','paper_boundary',paper_successor,label,path)
    typed_member('PaperCaseBoundary','paper_boundary',paper_successor,'nested-field','changes[0]',[3,0],[],'Shape')
    common_context('LocalAuthorityBoundary','local_boundary',boundary,'Context',[2])
    local_members('LocalAuthorityBoundary','local_boundary',boundary,'declaration',[3])
    account_members('LocalAuthorityBoundary','local_boundary',boundary,'account',[4])
    for field,offset in (('height',0),('transaction_index',1),('input_index',2)):
        typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-range','parts[0].issuance.'+field,[5,0,2,offset],-1,'Shape')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-length','parts[0].issuance.prevout',[5,0,2,3],bytes([1])*35,'Shape')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field','parts[0].actor',[5,0,1],'bad','Field')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field','associations[0].act.author',[6,0,3,1],'bad','Field')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field','associations[0].act.family',[6,0,3,3],'bad','Field')
    for field,offset in (('scan_from',3),('scan_through',4)):
        typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-range','parts[0].'+field,[5,0,offset],-1,'Shape')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-length','parts[0].prior.history_scope',[5,0,5,0],b'','Field')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-range','parts[0].prior.first_epoch',[5,0,5,1],1,'Shape')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-range','parts[0].prior.exclusive_end',[5,0,5,2],-1,'Shape')
    for label,path in (('parts[0]',[5,0]),('parts[0].issuance',[5,0,2]),('parts[0].prior',[5,0,5])):
        typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field',label,path,[],'Shape')
    common_context('LocalAuthorityBoundary','local_boundary',boundary,'associations[0].Context',[6,0,1])
    common_context('LocalAuthorityBoundary','local_boundary',boundary,'associations[0].account_reference.Context',[6,0,5,0])
    ref_members('LocalAuthorityBoundary','local_boundary',boundary,'associations[0].declaration',[6,0,4])
    for label,path in (('associations[0].act_position',[6,0,2]),('associations[0].act.sequence',[6,0,3,2]),
                       ('associations[0].account_reference.index',[6,0,5,1]),('associations[0].part_index',[6,0,6])):
        typed_member('LocalAuthorityBoundary','local_boundary',boundary,'member-range',label,path,-1,'Shape')
    typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field','associations[0].act.tag',[6,0,3,0],'other','Field')
    for label,path in (('associations[0]',[6,0]),('associations[0].act',[6,0,3]),
                       ('associations[0].account_reference',[6,0,5])):
        typed_member('LocalAuthorityBoundary','local_boundary',boundary,'nested-field',label,path,[],'Shape')
    paper_set = [1, context, [paper], []]
    three_active = [independent(paper) for _ in range(3)]
    for declaration, name in zip(three_active, ('a', 'z', 'y')):
        declaration[1] = ref(name)
    for name, expected, scenario, value in (
            ('context-unavailable', 'UnavailableContext', 'context', paper),
            ('selection-unavailable', 'UnavailableSelection', 'paper-selection', paper),
            ('selection-mismatch', 'SelectionMismatch', 'paper-selection-mismatch', paper),
            ('definition-unavailable', 'UnavailableEvaluation', 'paper-definition', paper)):
        new_operand('PaperCaseDeclaration', 'paper_declaration-'+name, value, expected, scenario=scenario)
    new_operand('PaperCaseDeclaration', 'paper_declaration-premise-before-content',
                variant(paper, [5], ref('other-rules')), 'UnavailableBinding', scenario='paper-premise-before-content')
    for name, expected, scenario, value in (
            ('context-unavailable', 'UnavailableContext', 'context', paper_set),
            ('selection-unavailable', 'UnavailableSelection', 'paper-selection', paper_set),
            ('selection-mismatch', 'SelectionMismatch', 'paper-selection-mismatch', paper_set),
            ('context-mismatch', 'Context', None, variant(paper_set, [1,2], 4)),
            ('declaration-content', 'DeclarationContent', 'paper-content', variant(paper_set, [2,0,5], ref('other-rules'))),
            ('scope', 'Scope', 'paper-scope', variant(paper_set, [2,0,3,3], 4)),
            ('case-set', 'CaseSet', 'paper-case-set', paper_set),
            ('predecessor-unavailable', 'UnavailablePredecessor', 'predecessor', paper_set),
            ('failed-case', 'FailedCase', 'paper-case', paper_set),
            ('collection-duplicate:active', 'Duplicate', None, [1,context,[paper,paper],[]]),
            ('collection-order:active', 'Order', None, [1, context, three_active, []]),
            ('collection-order:changes', 'Order', None, [1,context,[],[[1,ref('z')],[1,ref('a')]]]),
            ('collection-duplicate:changes', 'Duplicate', None, [1,context,[],[[1,ref('a')],[1,ref('a')]]]),
            ('order-before-duplicate', 'Order', None, [1,context,[],[[1,ref('z')],[1,ref('a')],[1,ref('a')]]])):
        new_operand('PaperCaseBoundary', 'paper_boundary-'+name, value, expected, scenario=scenario)
    for name, expected, scenario, value in (
            ('context-unavailable', 'UnavailableContext', 'context', local),
            ('selection-unavailable', 'UnavailableSelection', 'local-selection', local),
            ('selection-mismatch', 'SelectionMismatch', 'local-selection-mismatch', local),
            ('context-mismatch', 'Context', None, variant(local, [2,1], b'other-history')),
            ('evaluator-unavailable', 'UnavailableEvaluation', 'local-evaluator', local)):
        new_operand('LocalAuthorityDeclaration', 'local_declaration-'+name, value, expected, scenario=scenario)
    new_operand('LocalAuthorityDeclaration', 'local_declaration-premise-before-rules',
                variant(local, [4], ref('other-rules')), 'UnavailableBinding', scenario='local-premise-before-rules')
    for name, expected, scenario in (
            ('context-unavailable', 'UnavailableContext', 'context'),
            ('selection-before-binding', 'UnavailableRules', 'selection-before-binding'),
            ('binding-before-chain', 'Binding', 'binding-before-chain'),
            ('chain-before-history', 'Chain', 'chain-before-history')):
        new_operand('AuthorityAccount', 'account-'+name, account, expected, scenario=scenario)
    new_operand('AuthorityAccount', 'account-premise-before-minimum', account,
                'UnavailableBinding', scenario='account-premise-before-minimum')
    new_operand('AuthorityAccount', 'account-selected-context-premise', account,
                'UnavailableBinding', scenario='account-selected-context-premise')
    new_operand('AuthorityAccount', 'account-foreign-binding-refusal', account,
                'UnavailableBinding', scenario='account-foreign-binding-refusal')
    new_operand('AuthorityAccount', 'account-rules-premise', account,
                'UnavailableBinding', scenario='account-rules-premise')
    for name, expected, scenario, value in (
            ('selection-unavailable', 'UnavailableSelection', 'local-selection', boundary),
            ('selection-mismatch', 'SelectionMismatch', 'local-selection-mismatch', boundary),
            ('context-mismatch', 'Context', None, variant(boundary, [2,2], 4)),
            ('declaration', 'Declaration', None, variant(boundary, [3,1,2], 2)),
            ('rules', 'Rules', None, variant(boundary, [3,4], ref('other-rules'))),
            ('convention', 'Convention', None, variant(boundary, [3,5], ref('other-convention'))),
            ('run', 'Run', None, variant(boundary, [3,7], config[:-1]+bytes([1]))),
            ('scope', 'Scope', None, variant(boundary, [3,2,3], 4)),
            ('prefix', 'Prefix', None, variant(boundary, [4,2,0], 7)),
            ('overflow', 'Overflow', 'prefix-overflow', variant(boundary, [4,2,0], 2**64-1)),
            ('linkage-unavailable', 'UnavailableLinkage', 'linkage-unavailable', boundary),
            ('role-evaluator-unavailable', 'UnavailableEvaluation', 'role-unavailable', boundary),
            ('collection-order:parts', 'Order', None, variant(boundary, [5], [parts[1],parts[0]])),
            ('collection-duplicate:parts', 'Duplicate', None, variant(boundary, [5], [parts[0],parts[0]])),
            ('collection-order:associations', 'Order', None, variant(boundary, [6], [associations[1],associations[0]])),
            ('collection-duplicate:associations', 'Duplicate', None, variant(boundary, [6], [associations[0],associations[0]])),
            ('order-before-duplicate', 'Order', None, variant(boundary, [5], [parts[1],parts[0],parts[0]])),
            ('signature-before-membership', 'Signature', 'signature-before-membership', boundary),
            ('part-before-signature', 'Part', 'signature', variant(boundary, [6,0,6], 1)),
            ('actor-before-account', 'Reference', 'actor-before-account', variant(boundary, [6,0,5,1], 1)),
            ('account-before-part', 'Reference', None, variant(variant(boundary, [6,0,5,1], 1), [6,0,6], 1)),
            ('wrong-part-domain', 'Coverage', None, variant(boundary, [5,1,1], 'pn-devnet-v1/'+run.hex()+'/'+bytes([13]).hex()*32))):
        prefix = 'local-boundary-' if name in {'signature-before-membership', 'part-before-signature', 'actor-before-account', 'account-before-part'} else 'local_boundary-'
        new_operand('LocalAuthorityBoundary', prefix+name, value, expected, scenario=scenario)
    new_operand('LocalAuthorityBoundary', 'local_boundary-retained-premise-before-actor', boundary,
                'UnavailableBinding', scenario='retained-premise-before-actor')
    new_operand('LocalAuthorityBoundary', 'local_boundary-prefix-premise', boundary,
                'UnavailableBinding', scenario='local-boundary-prefix-premise')
    directory = Path(__file__).parent
    carrier_rows = json.loads((directory/'carrier-golden.json').read_text())['rows']
    formation_rows = json.loads((directory/'v3-golden.json').read_text())['rows']
    executable.append(dict(id='new:cross-feed-historical-formation-components', site='historical_isolation',
                           encoded=canonical(paper).hex(), expected='RefusedByForeignDecoder',
                           foreign_closure=carrier_rows[0]['closure'], foreign_header=formation_rows[0]['header'],
                           selected_context=public(context)))
    executable.append(dict(id='new:absent-required-local-with-empty-paper', site='missing_authority_case',
                           encoded=canonical([1,context,[],[]]).hex(), expected='MissingComponent',
                           local_component=None, selected_context=public(context)))
    executable.append(dict(id='new:positive-premise-retention', site='outcome_mapping',
                           encoded=canonical(boundary).hex(), expected='ConfirmedWithPremises',
                           evaluator='explicit-synthetic', binding='fixture-selected-complete-record',
                           selected_context=public(context)))
    executable.append(dict(id='new:incompatible-premise-aggregate', site='outcome_mapping',
                           encoded=canonical(boundary).hex(), expected='NotEvaluated',
                           evaluator='explicit-synthetic', binding='different-selected-complete-record',
                           selected_context=public(context)))
    executable.append(dict(id='new:explicit-empty-paper-and-transitions', site='verification_case_context',
                           encoded=canonical([1,context,[],[]]).hex(), expected='ConfirmedEmptyThenTransition',
                           prior_active=public([paper]), required_changes=public([[1,paper[1]]]),
                           selected_context=public(context)))
    return dict(schema=1, classes=['PaperCaseDeclaration', 'PaperCaseBoundary', 'LocalAuthorityDeclaration', 'AuthorityAccount', 'LocalAuthorityBoundary'],
                scope='Representation and future-result fixtures only; synthetic evaluator, no consensus or authenticity claim',
                rows=rows, allowances=allowances, account_formula=dict(chain=chain_formula, account=account_formula),
                block_inputs=block_values, scans=scans, byte_mutations=byte_mutations, run_limit_cases=[dict(limit=limit, measured=measured, ceiling=ceiling,
                    expected='Available' if measured <= ceiling else 'LocalUnavailable')
                    for limit, measured in (('declaration_outputs', 2), ('history_bytes', 100),
                    ('history_transactions', 3), ('active_entries', 2), ('scan_blocks', scans[0]['scan_blocks']),
                    ('scan_bytes', scans[0]['scan_bytes'])) for ceiling in (measured, measured-1)],
                expected_future_substitutions=substitutions,
                executable_descriptors=executable)


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
