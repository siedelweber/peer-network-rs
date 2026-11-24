//! Independent component fixture bytes pass the caller-selected fragment codecs.

use pn_epoch::authentication::ReadAllowances;
use pn_epoch::authentication::{
    AccountPin, ActorPart, Assessed, AssessmentPremises, AuthorityAccount, AuthorizedKeysWithPremises, BoundaryConsumer,
    BoundaryContext, Checked, ConsumerResult, CurrentAccountView, CurrentAuthorityQuery, EvaluatorSelection, Inability,
    LocalAuthorityBoundary, PaperCaseBoundary, PaperHistory, PinDisposition, PriorRange, Refusal, RetainedIdentity, Role,
};
use pn_host::boundary_components as codec;
use pn_records::cases::{ComponentRef, LocalAuthorityDeclaration, PaperCaseDeclaration};
use pn_records::closure::{ClosureAct, ClosureHeader, ClosureLeg};
use pn_records::commitments::{ActCommitments, ContentCommitment, DependencyCommitment, ProposalCommitment};
use pn_records::{ActId, PublicReference, StructuralBody};
use serde_json::Value;

// Independently transcribed from the admitted commit-one expected-id table.
const SITE_IDS: &[(&str, &[&str])] = &[
    (
        "account_order",
        &[
            "row:prefix-before-overflow",
            "row:superfluous-first-height",
            "row:wrong-claimed-minimum",
            "row:wrong-first-height",
            "row:prefix-overflow",
            "row:omitted-last-block",
            "byte:account-trailing",
            "byte:account-nonminimal-head",
            "byte:account-budget-before-canonical",
            "allowance:account-exact",
            "allowance:account-one-over",
            "substitution:no-evaluator",
            "substitution:unbound-account",
            "substitution:bad-binding",
            "substitution:bad-link",
            "substitution:bad-transaction-commitment",
            "substitution:bad-signed-evidence",
            "substitution:missing-acquisition",
            "substitution:missing-prior-epoch",
            "substitution:present-wrong-prior-context",
            "substitution:prior-not-obtainable",
            "new:account-mistyped-edition",
            "new:account-missing-member",
            "new:account-extra-member",
            "new:account-member-length:pin.block_hash",
            "new:account-member-range:prior.first_epoch",
            "new:account-context-unavailable",
            "new:account-selection-before-binding",
            "new:account-binding-before-chain",
            "new:account-chain-before-history",
            "new:account-shape-before-edition",
            "new:account-shape-before-field",
            "new:account-own-budget-before-canonical",
            "new:account-member-length:Context.run",
            "new:account-member-length:Context.history_scope",
            "new:account-member-range:Context.epoch",
            "new:account-nested-field:Context",
            "new:account-member-range:pin.height",
            "new:account-member-range:pin.buffer",
            "new:account-nested-field:pin",
            "new:account-nested-field:run_evidence",
            "new:account-member-range:chain_evidence.first_height",
            "new:account-nested-field:chain_evidence",
            "new:account-nested-field:chain_evidence.blocks[0]",
            "new:account-member-length:prior.history_scope",
            "new:account-member-range:prior.exclusive_end",
            "new:account-nested-field:prior",
            "new:account-premise-before-minimum",
            "new:account-selected-context-premise",
            "new:account-foreign-binding-refusal",
            "new:account-foreign-binding-inability",
            "new:account-rules-premise",
        ],
    ),
    ("account_values", &["row:shared-account", "row:empty-domain-account"]),
    ("historical_isolation", &["new:cross-feed-historical-formation-components"]),
    (
        "local_boundary_order",
        &[
            "row:coverage-before-reference",
            "row:wrong-act-position",
            "row:wrong-discriminator",
            "row:old-act-associated",
            "row:transplanted-account",
            "row:out-of-range-part",
            "row:wrong-part",
            "row:buffer-scan",
            "row:too-early-scan",
            "row:too-late-scan",
            "new:qualification-before-association-act",
            "new:qualification-before-coverage",
            "new:path-before-signature",
            "byte:boundary-trailing",
            "byte:boundary-nonminimal-head",
            "byte:boundary-budget-before-canonical",
            "allowance:local-boundary-exact",
            "allowance:local-boundary-one-over",
            "substitution:no-context",
            "substitution:annotation-only",
            "substitution:empty-active-set",
            "substitution:outside-covered-domain",
            "substitution:same-key-actor-swap",
            "substitution:changed-proposal",
            "substitution:bad-signature",
            "substitution:bad-approval",
            "substitution:wrong-material",
            "substitution:valid-signature-unauthorized",
            "new:local_boundary-mistyped-edition",
            "new:local_boundary-missing-member",
            "new:local_boundary-extra-member",
            "new:local_boundary-member-length:Context.run",
            "new:local_boundary-member-range:account.prior.first_epoch",
            "new:local_boundary-nested-field:declaration.reference.namespace",
            "new:local_boundary-selection-unavailable",
            "new:local_boundary-selection-mismatch",
            "new:local_boundary-context-mismatch",
            "new:local_boundary-declaration",
            "new:local_boundary-rules",
            "new:local_boundary-convention",
            "new:local_boundary-run",
            "new:local_boundary-scope",
            "new:local_boundary-prefix",
            "new:local_boundary-overflow",
            "new:local_boundary-linkage-unavailable",
            "new:local_boundary-role-evaluator-unavailable",
            "new:local_boundary-collection-order:parts",
            "new:local_boundary-collection-duplicate:parts",
            "new:local_boundary-collection-order:associations",
            "new:local_boundary-collection-duplicate:associations",
            "new:local_boundary-order-before-duplicate",
            "new:local-boundary-signature-before-membership",
            "new:local-boundary-part-before-signature",
            "new:local-boundary-actor-before-account",
            "new:local-boundary-account-before-part",
            "new:local_boundary-wrong-part-domain",
            "new:local_boundary-shape-before-edition",
            "new:local_boundary-shape-before-field",
            "new:local_boundary-account-allowance",
            "new:local_boundary-member-length:Context.history_scope",
            "new:local_boundary-member-range:Context.epoch",
            "new:local_boundary-nested-field:Context",
            "new:local_boundary-member-length:declaration.reference.namespace",
            "new:local_boundary-member-length:declaration.reference.name",
            "new:local_boundary-nested-field:declaration.reference.name",
            "new:local_boundary-member-range:declaration.reference.edition",
            "new:local_boundary-member-length:declaration.rules.namespace",
            "new:local_boundary-nested-field:declaration.rules.namespace",
            "new:local_boundary-member-length:declaration.rules.name",
            "new:local_boundary-nested-field:declaration.rules.name",
            "new:local_boundary-member-range:declaration.rules.edition",
            "new:local_boundary-member-length:declaration.convention.namespace",
            "new:local_boundary-nested-field:declaration.convention.namespace",
            "new:local_boundary-member-length:declaration.convention.name",
            "new:local_boundary-nested-field:declaration.convention.name",
            "new:local_boundary-member-range:declaration.convention.edition",
            "new:local_boundary-member-length:declaration.projection.namespace",
            "new:local_boundary-nested-field:declaration.projection.namespace",
            "new:local_boundary-member-length:declaration.projection.name",
            "new:local_boundary-nested-field:declaration.projection.name",
            "new:local_boundary-member-range:declaration.projection.edition",
            "new:local_boundary-member-length:declaration.second_party.reference.namespace",
            "new:local_boundary-nested-field:declaration.second_party.reference.namespace",
            "new:local_boundary-member-length:declaration.second_party.reference.name",
            "new:local_boundary-nested-field:declaration.second_party.reference.name",
            "new:local_boundary-member-range:declaration.second_party.reference.edition",
            "new:local_boundary-member-length:declaration.second_party.genesis_hash",
            "new:local_boundary-member-length:declaration.run_configuration",
            "new:local_boundary-member-length:declaration.scope.run",
            "new:local_boundary-member-length:declaration.scope.history_scope",
            "new:local_boundary-member-range:declaration.scope.announced_at",
            "new:local_boundary-member-range:declaration.scope.effective_at",
            "new:local_boundary-nested-field:declaration.scope",
            "new:local_boundary-nested-field:declaration.second_party",
            "new:local_boundary-member-length:account.Context.run",
            "new:local_boundary-member-length:account.Context.history_scope",
            "new:local_boundary-member-range:account.Context.epoch",
            "new:local_boundary-nested-field:account.Context",
            "new:local_boundary-member-length:account.pin.block_hash",
            "new:local_boundary-member-range:account.pin.height",
            "new:local_boundary-member-range:account.pin.buffer",
            "new:local_boundary-nested-field:account.pin",
            "new:local_boundary-nested-field:account.run_evidence",
            "new:local_boundary-member-range:account.chain_evidence.first_height",
            "new:local_boundary-nested-field:account.chain_evidence",
            "new:local_boundary-nested-field:account.chain_evidence.blocks[0]",
            "new:local_boundary-member-length:account.prior.history_scope",
            "new:local_boundary-member-range:account.prior.exclusive_end",
            "new:local_boundary-nested-field:account.prior",
            "new:local_boundary-member-range:parts[0].issuance.height",
            "new:local_boundary-member-range:parts[0].issuance.transaction_index",
            "new:local_boundary-member-range:parts[0].issuance.input_index",
            "new:local_boundary-member-length:parts[0].issuance.prevout",
            "new:local_boundary-nested-field:parts[0].actor",
            "new:local_boundary-nested-field:associations[0].act.author",
            "new:local_boundary-nested-field:associations[0].act.family",
            "new:local_boundary-member-range:parts[0].scan_from",
            "new:local_boundary-member-range:parts[0].scan_through",
            "new:local_boundary-member-length:parts[0].prior.history_scope",
            "new:local_boundary-member-range:parts[0].prior.first_epoch",
            "new:local_boundary-member-range:parts[0].prior.exclusive_end",
            "new:local_boundary-nested-field:parts[0]",
            "new:local_boundary-nested-field:parts[0].issuance",
            "new:local_boundary-nested-field:parts[0].prior",
            "new:local_boundary-member-length:associations[0].Context.run",
            "new:local_boundary-member-length:associations[0].Context.history_scope",
            "new:local_boundary-member-range:associations[0].Context.epoch",
            "new:local_boundary-nested-field:associations[0].Context",
            "new:local_boundary-member-length:associations[0].account_reference.Context.run",
            "new:local_boundary-member-length:associations[0].account_reference.Context.history_scope",
            "new:local_boundary-member-range:associations[0].account_reference.Context.epoch",
            "new:local_boundary-nested-field:associations[0].account_reference.Context",
            "new:local_boundary-member-length:associations[0].declaration.namespace",
            "new:local_boundary-nested-field:associations[0].declaration.namespace",
            "new:local_boundary-member-length:associations[0].declaration.name",
            "new:local_boundary-nested-field:associations[0].declaration.name",
            "new:local_boundary-member-range:associations[0].declaration.edition",
            "new:local_boundary-member-range:associations[0].act_position",
            "new:local_boundary-member-range:associations[0].act.sequence",
            "new:local_boundary-member-range:associations[0].account_reference.index",
            "new:local_boundary-member-range:associations[0].part_index",
            "new:local_boundary-nested-field:associations[0].act.tag",
            "new:local_boundary-nested-field:associations[0]",
            "new:local_boundary-nested-field:associations[0].act",
            "new:local_boundary-nested-field:associations[0].account_reference",
            "new:local_boundary-part-layout",
            "new:local_boundary-association-layout",
            "new:local_boundary-nested-declaration-edition",
            "new:local_boundary-nested-account-edition",
            "new:local_boundary-nested-account-blocks-budget",
            "new:local_boundary-retained-premise-before-actor",
            "new:local_boundary-prefix-premise",
        ],
    ),
    ("local_boundary_values", &["row:local-boundary", "row:empty-domain-boundary"]),
    (
        "local_declaration_order",
        &[
            "row:declaration-before-rules",
            "row:declaration-scope-mismatch",
            "row:declaration-run-mismatch",
            "row:declaration-ref-mismatch",
            "row:declaration-convention-mismatch",
            "row:declaration-rules-mismatch",
            "byte:local-trailing",
            "byte:local-nonminimal-head",
            "byte:local-budget-before-canonical",
            "allowance:local-declaration-exact",
            "allowance:local-declaration-one-over",
            "new:local_declaration-mistyped-edition",
            "new:local_declaration-missing-member",
            "new:local_declaration-extra-member",
            "new:local_declaration-member-length:second_party.genesis_hash",
            "new:local_declaration-member-range:reference.edition",
            "new:local_declaration-nested-field:reference.namespace",
            "new:local_declaration-context-unavailable",
            "new:local_declaration-selection-unavailable",
            "new:local_declaration-shape-before-edition",
            "new:local_declaration-shape-before-field",
            "new:local_declaration-selection-mismatch",
            "new:local_declaration-context-mismatch",
            "new:local_declaration-evaluator-unavailable",
            "new:local_declaration-member-length:reference.namespace",
            "new:local_declaration-member-length:reference.name",
            "new:local_declaration-nested-field:reference.name",
            "new:local_declaration-member-length:rules.namespace",
            "new:local_declaration-nested-field:rules.namespace",
            "new:local_declaration-member-length:rules.name",
            "new:local_declaration-nested-field:rules.name",
            "new:local_declaration-member-range:rules.edition",
            "new:local_declaration-member-length:convention.namespace",
            "new:local_declaration-nested-field:convention.namespace",
            "new:local_declaration-member-length:convention.name",
            "new:local_declaration-nested-field:convention.name",
            "new:local_declaration-member-range:convention.edition",
            "new:local_declaration-member-length:projection.namespace",
            "new:local_declaration-nested-field:projection.namespace",
            "new:local_declaration-member-length:projection.name",
            "new:local_declaration-nested-field:projection.name",
            "new:local_declaration-member-range:projection.edition",
            "new:local_declaration-member-length:second_party.reference.namespace",
            "new:local_declaration-nested-field:second_party.reference.namespace",
            "new:local_declaration-member-length:second_party.reference.name",
            "new:local_declaration-nested-field:second_party.reference.name",
            "new:local_declaration-member-range:second_party.reference.edition",
            "new:local_declaration-member-length:run_configuration",
            "new:local_declaration-member-length:scope.run",
            "new:local_declaration-member-length:scope.history_scope",
            "new:local_declaration-member-range:scope.announced_at",
            "new:local_declaration-member-range:scope.effective_at",
            "new:local_declaration-nested-field:scope",
            "new:local_declaration-nested-field:second_party",
            "new:local_declaration-premise-before-rules",
        ],
    ),
    ("local_declaration_values", &["row:local-declaration"]),
    (
        "missing_authority_case",
        &["substitution:no-courtesy", "new:absent-required-local-with-empty-paper"],
    ),
    (
        "outcome_mapping",
        &["new:positive-premise-retention", "new:incompatible-premise-aggregate"],
    ),
    (
        "paper_boundary_order",
        &[
            "row:descending-order",
            "row:order-before-duplicate",
            "row:successor-not-active",
            "row:spurious-change",
            "row:conflicting-change",
            "row:duplicate-withdrawal",
            "row:omitted-withdrawal",
            "byte:paper-boundary-trailing",
            "byte:paper-boundary-nonminimal-head",
            "byte:paper-boundary-budget-before-canonical",
            "allowance:paper-boundary-exact",
            "allowance:paper-boundary-one-over",
            "substitution:missing-paper-component",
            "substitution:unknown-paper-evaluator",
            "new:paper_boundary-mistyped-edition",
            "new:paper_boundary-missing-member",
            "new:paper_boundary-extra-member",
            "new:paper_boundary-member-length:Context.run",
            "new:paper_boundary-member-range:active[0].reference.edition",
            "new:paper_boundary-nested-field:active[0].reference.namespace",
            "new:paper_boundary-context-unavailable",
            "new:paper_boundary-selection-unavailable",
            "new:paper_boundary-shape-before-edition",
            "new:paper_boundary-shape-before-field",
            "new:paper_boundary-selection-mismatch",
            "new:paper_boundary-context-mismatch",
            "new:paper_boundary-declaration-content",
            "new:paper_boundary-scope",
            "new:paper_boundary-case-set",
            "new:paper_boundary-predecessor-unavailable",
            "new:paper_boundary-failed-case",
            "new:paper_boundary-collection-duplicate:active",
            "new:paper_boundary-collection-order:active",
            "new:paper_boundary-collection-order:changes",
            "new:paper_boundary-collection-duplicate:changes",
            "new:paper_boundary-order-before-duplicate",
            "new:paper_boundary-member-length:Context.history_scope",
            "new:paper_boundary-member-range:Context.epoch",
            "new:paper_boundary-nested-field:Context",
            "new:paper_boundary-member-range:active[0].kind",
            "new:paper_boundary-member-length:active[0].reference.namespace",
            "new:paper_boundary-member-length:active[0].reference.name",
            "new:paper_boundary-nested-field:active[0].reference.name",
            "new:paper_boundary-member-length:active[0].second_party.namespace",
            "new:paper_boundary-nested-field:active[0].second_party.namespace",
            "new:paper_boundary-member-length:active[0].second_party.name",
            "new:paper_boundary-nested-field:active[0].second_party.name",
            "new:paper_boundary-member-range:active[0].second_party.edition",
            "new:paper_boundary-member-length:active[0].rules.namespace",
            "new:paper_boundary-nested-field:active[0].rules.namespace",
            "new:paper_boundary-member-length:active[0].rules.name",
            "new:paper_boundary-nested-field:active[0].rules.name",
            "new:paper_boundary-member-range:active[0].rules.edition",
            "new:paper_boundary-member-length:active[0].convention.namespace",
            "new:paper_boundary-nested-field:active[0].convention.namespace",
            "new:paper_boundary-member-length:active[0].convention.name",
            "new:paper_boundary-nested-field:active[0].convention.name",
            "new:paper_boundary-member-range:active[0].convention.edition",
            "new:paper_boundary-member-length:active[0].projection.namespace",
            "new:paper_boundary-nested-field:active[0].projection.namespace",
            "new:paper_boundary-member-length:active[0].projection.name",
            "new:paper_boundary-nested-field:active[0].projection.name",
            "new:paper_boundary-member-range:active[0].projection.edition",
            "new:paper_boundary-member-length:active[0].data_selection.rule.namespace",
            "new:paper_boundary-nested-field:active[0].data_selection.rule.namespace",
            "new:paper_boundary-member-length:active[0].data_selection.rule.name",
            "new:paper_boundary-nested-field:active[0].data_selection.rule.name",
            "new:paper_boundary-member-range:active[0].data_selection.rule.edition",
            "new:paper_boundary-member-length:active[0].data_selection.unit.namespace",
            "new:paper_boundary-nested-field:active[0].data_selection.unit.namespace",
            "new:paper_boundary-member-length:active[0].data_selection.unit.name",
            "new:paper_boundary-nested-field:active[0].data_selection.unit.name",
            "new:paper_boundary-member-range:active[0].data_selection.unit.edition",
            "new:paper_boundary-member-length:active[0].scope.run",
            "new:paper_boundary-member-length:active[0].scope.history_scope",
            "new:paper_boundary-member-range:active[0].scope.announced_at",
            "new:paper_boundary-member-range:active[0].scope.effective_at",
            "new:paper_boundary-nested-field:active[0].scope",
            "new:paper_boundary-nested-field:active[0].data_selection",
            "new:paper_boundary-nested-field:active[0]",
            "new:paper_boundary-member-length:changes[0].old.namespace",
            "new:paper_boundary-nested-field:changes[0].old.namespace",
            "new:paper_boundary-member-length:changes[0].old.name",
            "new:paper_boundary-nested-field:changes[0].old.name",
            "new:paper_boundary-member-range:changes[0].old.edition",
            "new:paper_boundary-member-length:changes[0].new.namespace",
            "new:paper_boundary-nested-field:changes[0].new.namespace",
            "new:paper_boundary-member-length:changes[0].new.name",
            "new:paper_boundary-nested-field:changes[0].new.name",
            "new:paper_boundary-member-range:changes[0].new.edition",
            "new:paper_boundary-nested-field:changes[0]",
            "new:paper_boundary-nested-edition",
            "new:paper_boundary-nested-kind",
            "new:paper_boundary-nested-history-budget",
        ],
    ),
    (
        "paper_boundary_values",
        &[
            "row:empty-paper-set",
            "row:first-adoption",
            "row:unchanged",
            "row:successor",
            "row:withdrawal",
        ],
    ),
    (
        "paper_declaration_order",
        &[
            "row:scope-not-in-force",
            "row:edition-before-kind",
            "row:wrong-history",
            "row:changed-body-same-ref",
            "row:wrong-kind",
            "byte:paper-trailing",
            "byte:paper-nonminimal-head",
            "byte:paper-budget-before-canonical",
            "allowance:paper-declaration-exact",
            "allowance:paper-declaration-one-over",
            "substitution:unknown-selected-edition",
            "new:paper_declaration-mistyped-edition",
            "new:paper_declaration-missing-member",
            "new:paper_declaration-extra-member",
            "new:paper_declaration-member-length:scope.run",
            "new:paper_declaration-member-range:reference.edition",
            "new:paper_declaration-nested-field:reference.namespace",
            "new:paper_declaration-context-unavailable",
            "new:paper_declaration-selection-unavailable",
            "new:paper_declaration-shape-before-edition",
            "new:paper_declaration-shape-before-field",
            "new:paper_declaration-selection-mismatch",
            "new:paper_declaration-definition-unavailable",
            "new:paper_declaration-member-range:kind",
            "new:paper_declaration-member-length:reference.namespace",
            "new:paper_declaration-member-length:reference.name",
            "new:paper_declaration-nested-field:reference.name",
            "new:paper_declaration-member-length:second_party.namespace",
            "new:paper_declaration-nested-field:second_party.namespace",
            "new:paper_declaration-member-length:second_party.name",
            "new:paper_declaration-nested-field:second_party.name",
            "new:paper_declaration-member-range:second_party.edition",
            "new:paper_declaration-member-length:rules.namespace",
            "new:paper_declaration-nested-field:rules.namespace",
            "new:paper_declaration-member-length:rules.name",
            "new:paper_declaration-nested-field:rules.name",
            "new:paper_declaration-member-range:rules.edition",
            "new:paper_declaration-member-length:convention.namespace",
            "new:paper_declaration-nested-field:convention.namespace",
            "new:paper_declaration-member-length:convention.name",
            "new:paper_declaration-nested-field:convention.name",
            "new:paper_declaration-member-range:convention.edition",
            "new:paper_declaration-member-length:projection.namespace",
            "new:paper_declaration-nested-field:projection.namespace",
            "new:paper_declaration-member-length:projection.name",
            "new:paper_declaration-nested-field:projection.name",
            "new:paper_declaration-member-range:projection.edition",
            "new:paper_declaration-member-length:data_selection.rule.namespace",
            "new:paper_declaration-nested-field:data_selection.rule.namespace",
            "new:paper_declaration-member-length:data_selection.rule.name",
            "new:paper_declaration-nested-field:data_selection.rule.name",
            "new:paper_declaration-member-range:data_selection.rule.edition",
            "new:paper_declaration-member-length:data_selection.unit.namespace",
            "new:paper_declaration-nested-field:data_selection.unit.namespace",
            "new:paper_declaration-member-length:data_selection.unit.name",
            "new:paper_declaration-nested-field:data_selection.unit.name",
            "new:paper_declaration-member-range:data_selection.unit.edition",
            "new:paper_declaration-member-length:scope.history_scope",
            "new:paper_declaration-member-range:scope.announced_at",
            "new:paper_declaration-member-range:scope.effective_at",
            "new:paper_declaration-nested-field:scope",
            "new:paper_declaration-nested-field:data_selection",
            "new:paper_declaration-kind-zero-null-unit",
            "new:paper_declaration-kind-one-ref-unit",
            "new:paper_declaration-premise-before-content",
        ],
    ),
    ("paper_declaration_values", &["row:provenance", "row:author-case"]),
    ("verification_case_context", &["new:explicit-empty-paper-and-transitions"]),
];

fn expected_site_ids(site: &str) -> &'static [&'static str] {
    SITE_IDS
        .iter()
        .find_map(|(name, ids)| (*name == site).then_some(*ids))
        .unwrap_or_else(|| panic!("unknown boundary site {site}"))
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../act-authentication/tests/boundary-golden.json")).unwrap()
}

fn decoded_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn assert_site_ids(site: &str, executed: &[String]) {
    // The complete corpus is a shared fixture-integrity precondition of every
    // site; it is not an additional assertion about historical decoding.
    let mut corpus = fixture()["executable_descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut registered = SITE_IDS
        .iter()
        .flat_map(|(_, ids)| ids.iter().map(|id| (*id).to_owned()))
        .collect::<Vec<_>>();
    corpus.sort();
    registered.sort();
    assert_eq!(corpus, registered, "complete descriptor registration");
    let mut expected = expected_site_ids(site).iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
    let mut actual = executed.to_vec();
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected, "executed descriptor ids at {site}");
}

fn limits() -> ReadAllowances {
    ReadAllowances {
        encoded_bytes: 1_000_000,
        history_scope_bytes: 1_000_000,
        declarations: 100,
        transitions: 100,
        account_bytes: 1_000_000,
        blocks: 100,
        block_bytes: 1_000_000,
        parts: 100,
        associations: 100,
        prior_epochs: 100,
    }
}

fn rows(family: &str) -> Vec<Value> {
    fixture()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["family"] == family && row["expected"] == "RepresentationEqual")
        .cloned()
        .collect()
}

fn check_rows(family: &str, mut check: impl FnMut(&[u8], &ReadAllowances) -> Vec<u8>) -> Vec<String> {
    let mut names = Vec::new();
    for row in rows(family) {
        let bytes = decoded_hex(row["encoded"].as_str().unwrap());
        assert_eq!(check(&bytes, &limits()), bytes, "{}", row["name"]);
        names.push(row["name"].as_str().unwrap().to_owned());
    }
    names
}

#[derive(Clone, Debug)]
struct FixtureHeader {
    id: ActId,
    body: StructuralBody,
    commitments: ActCommitments,
}

impl ClosureHeader for FixtureHeader {
    fn bytes(&self) -> &[u8] {
        &[]
    }
    fn id(&self) -> &ActId {
        &self.id
    }
    fn body(&self) -> &StructuralBody {
        &self.body
    }
    fn legs(&self) -> Vec<ClosureLeg<'_>> {
        Vec::new()
    }
    fn protocol_references(&self) -> &[PublicReference] {
        &[]
    }
    fn commitments(&self) -> &ActCommitments {
        &self.commitments
    }
}

fn fixture_acts(boundary: &LocalAuthorityBoundary) -> Vec<ClosureAct<FixtureHeader>> {
    boundary
        .associations
        .iter()
        .map(|association| {
            ClosureAct::new(
                FixtureHeader {
                    id: association.act.clone(),
                    body: StructuralBody {
                        settlement: None,
                        license: None,
                        asserted_parents: Vec::new(),
                        layout: pn_records::Layout::Binary,
                        quantities: Vec::new(),
                    },
                    commitments: ActCommitments {
                        proposal: ProposalCommitment {
                            recipe: String::new(),
                            bytes: [0; 32],
                        },
                        content: ContentCommitment {
                            recipe: String::new(),
                            bytes: [0; 32],
                        },
                        dependency: DependencyCommitment {
                            recipe: String::new(),
                            bytes: [0; 32],
                        },
                    },
                },
                Vec::new(),
                [0; 64],
                [0; 64],
                boundary.context.epoch,
                association.act_position,
                0,
            )
        })
        .collect()
}

#[derive(Debug)]
pub(super) struct Synthetic<'a> {
    pub(super) context: BoundaryContext,
    paper: PaperCaseBoundary,
    local: LocalAuthorityBoundary,
    minimum: u64,
    predecessor: Vec<PaperCaseDeclaration>,
    failure: Option<&'a str>,
}

impl Synthetic<'_> {
    pub(super) fn from_fixture() -> Self {
        let fixture = fixture();
        let row = |name: &str| {
            fixture["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap()
        };
        let paper = codec::decode_paper_boundary(
            Some(&decoded_hex(row("empty-paper-set")["encoded"].as_str().unwrap())),
            1,
            &limits(),
        )
        .unwrap();
        let local = codec::decode_local_boundary(
            Some(&decoded_hex(row("local-boundary")["encoded"].as_str().unwrap())),
            1,
            &limits(),
        )
        .unwrap();
        Self {
            context: local.context.clone(),
            paper,
            minimum: 5,
            predecessor: Vec::new(),
            local,
            failure: None,
        }
    }

    fn premises(&self) -> AssessmentPremises {
        AssessmentPremises {
            evaluator: EvaluatorSelection::ExplicitSyntheticPremise,
            consensus: "fixture-selected-consensus".to_owned(),
            binding: "fixture-selected-complete-record".to_owned(),
            context: self.context.clone(),
        }
    }

    fn okay<T>(&self, value: T) -> ConsumerResult<T> {
        ConsumerResult::Confirmed(Assessed {
            value,
            premises: self.premises(),
        })
    }

    fn different<T>(&self, value: T) -> ConsumerResult<T> {
        let mut premises = self.premises();
        "other-selected-record".clone_into(&mut premises.binding);
        ConsumerResult::Confirmed(Assessed { value, premises })
    }

    fn unavailable<T>(&self, value: Inability) -> ConsumerResult<T> {
        ConsumerResult::Unavailable(Assessed {
            value,
            premises: self.premises(),
        })
    }

    fn refused<T>(&self, value: Refusal) -> ConsumerResult<T> {
        ConsumerResult::Refused(Assessed {
            value,
            premises: self.premises(),
        })
    }

    fn foreign_refusal<T>(&self, value: Refusal) -> ConsumerResult<T> {
        let mut premises = self.premises();
        "other-selected-record".clone_into(&mut premises.binding);
        ConsumerResult::Refused(Assessed { value, premises })
    }

    fn foreign_inability<T>(&self, value: Inability) -> ConsumerResult<T> {
        let mut premises = self.premises();
        "other-selected-record".clone_into(&mut premises.binding);
        ConsumerResult::Unavailable(Assessed { value, premises })
    }
}

impl BoundaryConsumer for Synthetic<'_> {
    fn required_boundary_context(&self, _candidate: &BoundaryContext) -> ConsumerResult<BoundaryContext> {
        if self.failure == Some("context") {
            self.unavailable(Inability::UnavailableContext)
        } else if self.failure == Some("account-selected-context-premise") {
            self.different(self.context.clone())
        } else {
            self.okay(self.context.clone())
        }
    }
    fn paper_declaration_definition(
        &self,
        _selected: &BoundaryContext,
        reference: &ComponentRef,
    ) -> ConsumerResult<PaperCaseDeclaration> {
        if self.failure == Some("paper-definition") {
            return self.unavailable(Inability::UnavailableEvaluation);
        }
        if self.failure == Some("paper-selection") {
            return self.unavailable(Inability::UnavailableSelection);
        }
        if self.failure == Some("paper-selection-mismatch") {
            return self.refused(Refusal::SelectionMismatch);
        }
        if matches!(self.failure, Some("paper-content" | "paper-premise-before-content")) {
            let base = row("provenance");
            let value =
                codec::decode_paper_declaration(Some(&decoded_hex(base["encoded"].as_str().unwrap())), 1, &limits()).unwrap();
            return if self.failure == Some("paper-premise-before-content") {
                self.different(value)
            } else {
                self.okay(value)
            };
        }
        let selected = self.paper.active.iter().find(|candidate| &candidate.reference == reference);
        match selected {
            Some(value) => self.okay(value.clone()),
            None => self.unavailable(Inability::UnavailableSelection),
        }
    }
    fn local_declaration_definition(&self, _selected: &BoundaryContext) -> ConsumerResult<LocalAuthorityDeclaration> {
        match self.failure {
            Some("local-selection") => self.unavailable(Inability::UnavailableSelection),
            Some("local-selection-mismatch") => self.refused(Refusal::SelectionMismatch),
            Some("local-evaluator") => self.unavailable(Inability::UnavailableEvaluation),
            Some("local-premise-before-rules") => self.different(self.local.declaration.clone()),
            _ => self.okay(self.local.declaration.clone()),
        }
    }
    fn paper_declaration_history(&self, _candidate: &PaperCaseBoundary) -> ConsumerResult<PaperHistory> {
        if self.failure == Some("predecessor") {
            return self.unavailable(Inability::UnavailablePredecessor);
        }
        if self.failure == Some("paper-case-set") {
            return self.okay(PaperHistory {
                current: Vec::new(),
                predecessor: Some(Vec::new()),
            });
        }
        self.okay(PaperHistory {
            current: self.paper.active.clone(),
            predecessor: Some(self.predecessor.clone()),
        })
    }
    fn prior_epoch(&self, _candidate: &PriorRange) -> ConsumerResult<()> {
        match self.failure {
            Some("missing-prior") => self.refused(Refusal::MissingEvidence),
            Some("prior" | "chain-before-history") => self.refused(Refusal::History),
            _ => self.okay(()),
        }
    }
    fn compare_marker_prefix(&self, candidate: &AccountPin) -> ConsumerResult<()> {
        if self.failure == Some("linkage-unavailable") {
            return self.unavailable(Inability::UnavailableLinkage);
        }
        if *candidate == self.local.account.pin {
            if self.failure == Some("local-boundary-prefix-premise") {
                self.different(())
            } else {
                self.okay(())
            }
        } else {
            self.refused(Refusal::Prefix)
        }
    }
    fn selected_chain_rules(&self, _selected: &BoundaryContext) -> ConsumerResult<()> {
        if matches!(self.failure, Some("rules" | "selection-before-binding")) {
            self.unavailable(Inability::UnavailableRules)
        } else if self.failure == Some("account-rules-premise") {
            self.different(())
        } else {
            self.okay(())
        }
    }
    fn compare_public_binding(&self, _candidate: &AuthorityAccount) -> ConsumerResult<()> {
        match self.failure {
            Some("account-foreign-binding-refusal") => self.foreign_refusal(Refusal::Binding),
            Some("account-foreign-binding-inability") => self.foreign_inability(Inability::UnavailableEvaluation),
            Some("binding" | "binding-before-chain" | "selection-before-binding") => self.refused(Refusal::Binding),
            Some("binding-unavailable") => self.unavailable(Inability::UnavailableBinding),
            _ => self.okay(()),
        }
    }
    fn evaluate_chain_evidence(&self, _candidate: &AuthorityAccount) -> ConsumerResult<()> {
        match self.failure {
            Some("chain" | "chain-before-history" | "binding-before-chain") => self.refused(Refusal::Chain),
            Some("chain-unavailable") => self.unavailable(Inability::UnavailableEvaluation),
            _ => self.okay(()),
        }
    }
    fn qualified_first_height(&self, _candidate: &AuthorityAccount) -> ConsumerResult<u64> {
        if matches!(
            self.failure,
            Some("qualification-before-association-act" | "qualification-before-coverage")
        ) {
            return self.refused(Refusal::Qualification);
        }
        if matches!(
            self.failure,
            Some("account-premise-before-minimum" | "account-selected-context-premise")
        ) {
            self.different(self.minimum + 1)
        } else {
            self.okay(self.minimum)
        }
    }
    fn compare_retained_act<H: ClosureHeader>(&self, candidate: &ClosureAct<H>) -> ConsumerResult<RetainedIdentity> {
        if self.failure == Some("retained") {
            return self.refused(Refusal::RetainedActRefusal);
        }
        if self.failure == Some("retained-premise-before-actor") {
            return self.different(RetainedIdentity {
                actor: "pn-devnet-v1/wrong".to_owned(),
                signer_key_hash: [7; 32],
            });
        }
        if matches!(self.failure, Some("wrong-actor" | "actor-before-account")) {
            return self.okay(RetainedIdentity {
                actor: "pn-devnet-v1/wrong".to_owned(),
                signer_key_hash: [7; 32],
            });
        }
        self.okay(RetainedIdentity {
            actor: candidate.header().id().author.clone(),
            signer_key_hash: [7; 32],
        })
    }
    fn verify_recorded_role<H: ClosureHeader>(&self, _candidate: &ClosureAct<H>, _role: Role) -> ConsumerResult<()> {
        match self.failure {
            Some("signature" | "signature-before-membership" | "path-before-signature") => self.refused(Refusal::Signature),
            Some("role-unavailable") => self.unavailable(Inability::UnavailableEvaluation),
            _ => self.okay(()),
        }
    }
    fn authority_set(&self, _account: &AuthorityAccount, part: &ActorPart) -> ConsumerResult<AuthorizedKeysWithPremises> {
        if self.failure == Some("path-before-signature") {
            return self.refused(Refusal::Path);
        }
        if self.failure == Some("not-covered") {
            return self.unavailable(Inability::NotCovered);
        }
        if matches!(self.failure, Some("membership" | "signature-before-membership")) {
            return self.okay(AuthorizedKeysWithPremises {
                actor: part.actor.clone(),
                keys: Vec::new(),
                pin: self.local.account.pin.clone(),
            });
        }
        self.okay(AuthorizedKeysWithPremises {
            actor: part.actor.clone(),
            keys: vec![[7; 32]],
            pin: self.local.account.pin.clone(),
        })
    }
    fn evaluate_case(&self, _declaration: &PaperCaseDeclaration) -> ConsumerResult<()> {
        match self.failure {
            Some("paper-case") => self.refused(Refusal::FailedCase),
            Some("paper-unavailable") => self.unavailable(Inability::UnavailableEvaluation),
            _ => self.okay(()),
        }
    }
}

/// Claim: The selected producer and consumer agree on both complete admitted paper declaration encodings.
/// ´claim:publication:paper-declaration-values´
/// ´test:integration:paper-declaration-values´
#[test]
fn paper_declaration_values() {
    let names = check_rows("PaperCaseDeclaration", |bytes, limits| {
        codec::encode_paper_declaration(&codec::decode_paper_declaration(Some(bytes), 1, limits).unwrap(), limits).unwrap()
    });
    assert_eq!(names, ["provenance", "author-case"]);
    assert_site_ids(
        "paper_declaration_values",
        &names.iter().map(|name| format!("row:{name}")).collect::<Vec<_>>(),
    );
}

/// Claim: Complete paper set and transition values agree with all five independent encodings.
/// ´claim:publication:paper-boundary-values´
/// ´test:integration:paper-boundary-values´
#[test]
fn paper_boundary_values() {
    let names = check_rows("PaperCaseBoundary", |bytes, limits| {
        codec::encode_paper_boundary(&codec::decode_paper_boundary(Some(bytes), 1, limits).unwrap(), limits).unwrap()
    });
    assert_eq!(
        names,
        ["empty-paper-set", "first-adoption", "unchanged", "successor", "withdrawal"]
    );
    assert_site_ids(
        "paper_boundary_values",
        &names.iter().map(|name| format!("row:{name}")).collect::<Vec<_>>(),
    );
}

/// Claim: The complete independently selected local declaration agrees with its producer and consumer.
/// ´claim:publication:local-declaration-values´
/// ´test:integration:local-declaration-values´
#[test]
fn local_declaration_values() {
    let names = check_rows("LocalAuthorityDeclaration", |bytes, limits| {
        codec::encode_local_declaration(&codec::decode_local_declaration(Some(bytes), 1, limits).unwrap(), limits).unwrap()
    });
    assert_eq!(names, ["local-declaration"]);
    assert_site_ids(
        "local_declaration_values",
        &names.iter().map(|name| format!("row:{name}")).collect::<Vec<_>>(),
    );
}

/// Claim: Exact account encoding and allowance formulas agree with the independent shared and empty-domain inputs.
/// ´claim:publication:authority-account-values´
/// ´test:integration:account-values´
#[test]
fn account_values() {
    let names = check_rows("AuthorityAccount", |bytes, limits| {
        codec::encode_account(&codec::decode_account(Some(bytes), 1, limits).unwrap(), limits).unwrap()
    });
    assert_eq!(names, ["shared-account", "empty-domain-account"]);
    let golden = fixture();
    let expected_bytes = golden["account_formula"]["account"].as_u64().unwrap();
    let shared = row("shared-account");
    assert_eq!(shared["encoded_bytes"].as_u64().unwrap(), expected_bytes);
    let encoded = decoded_hex(shared["encoded"].as_str().unwrap());
    let account = codec::decode_account(Some(&encoded), 1, &limits()).unwrap();
    let mut exact = limits();
    exact.encoded_bytes = usize::try_from(expected_bytes).unwrap();
    exact.account_bytes = exact.encoded_bytes;
    assert_eq!(codec::encode_account(&account, &exact).unwrap(), encoded);
    let mut one_less = exact;
    one_less.encoded_bytes -= 1;
    assert_eq!(
        codec::encode_account(&account, &one_less),
        Err(codec::FragmentError::UnavailableBudget)
    );
    assert_site_ids(
        "account_values",
        &names.iter().map(|name| format!("row:{name}")).collect::<Vec<_>>(),
    );
}

/// Claim: Complete local component values agree with the independent shared and empty-domain encodings.
/// ´claim:publication:local-boundary-values´
/// ´test:integration:local-boundary-values´
#[test]
fn local_boundary_values() {
    let names = check_rows("LocalAuthorityBoundary", |bytes, limits| {
        codec::encode_local_boundary(&codec::decode_local_boundary(Some(bytes), 1, limits).unwrap(), limits).unwrap()
    });
    assert_eq!(names, ["local-boundary", "empty-domain-boundary"]);
    assert_site_ids(
        "local_boundary_values",
        &names.iter().map(|name| format!("row:{name}")).collect::<Vec<_>>(),
    );
}

fn row(name: &str) -> Value {
    fixture()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap()
        .clone()
}

fn matches_expected<T>(actual: &Checked<T>, expected: &str) -> bool {
    let refusal = match actual {
        Checked::Refused(cause) => Some(*cause),
        Checked::RefusedWithPremises(value) => Some(value.value),
        _ => None,
    };
    let inability = match actual {
        Checked::Unavailable(cause) => Some(*cause),
        Checked::UnavailableWithPremises(value) => Some(value.value),
        _ => None,
    };
    match expected {
        "ConfirmedWithPremises" | "ConfirmedEmptyThenTransition" | "LocalResultUnchanged" => {
            matches!(actual, Checked::Confirmed(_))
        }
        "NotEvaluated" => inability == Some(Inability::NotEvaluated),
        "NotCovered" => inability == Some(Inability::NotCovered),
        "UnavailableBinding" => inability == Some(Inability::UnavailableBinding),
        "UnavailableBindingWithSelectedPremises" => matches!(actual, Checked::UnavailableWithPremises(value)
            if value.value == Inability::UnavailableBinding && value.premises.binding == "fixture-selected-complete-record"),
        "UnavailableBindingWithForeignPremises" => matches!(actual, Checked::UnavailableWithPremises(value)
            if value.value == Inability::UnavailableBinding && value.premises.binding == "other-selected-record"),
        "UnavailableContext" => inability == Some(Inability::UnavailableContext),
        "UnavailableEvaluation" => inability == Some(Inability::UnavailableEvaluation),
        "UnavailableLinkage" => inability == Some(Inability::UnavailableLinkage),
        "UnavailablePredecessor" => inability == Some(Inability::UnavailablePredecessor),
        "UnavailableRules" => inability == Some(Inability::UnavailableRules),
        "UnavailableSelection" => inability == Some(Inability::UnavailableSelection),
        "Context" => refusal == Some(Refusal::Context),
        "SelectionMismatch" => refusal == Some(Refusal::SelectionMismatch),
        "Declaration" => refusal == Some(Refusal::Declaration),
        "DeclarationContent" => refusal == Some(Refusal::DeclarationContent),
        "Rules" => refusal == Some(Refusal::Rules),
        "Convention" => refusal == Some(Refusal::Convention),
        "Run" => refusal == Some(Refusal::Run),
        "Scope" => refusal == Some(Refusal::Scope),
        "CaseSet" => refusal == Some(Refusal::CaseSet),
        "Transition" => refusal == Some(Refusal::Transition),
        "FailedCase" => refusal == Some(Refusal::FailedCase),
        "Prefix" => refusal == Some(Refusal::Prefix),
        "Overflow" => refusal == Some(Refusal::Overflow),
        "MissingEvidence" => refusal == Some(Refusal::MissingEvidence),
        "Binding" => refusal == Some(Refusal::Binding),
        "Chain" => refusal == Some(Refusal::Chain),
        "History" => refusal == Some(Refusal::History),
        "Qualification" => refusal == Some(Refusal::Qualification),
        "Actor" => refusal == Some(Refusal::Actor),
        "Coverage" => refusal == Some(Refusal::Coverage),
        "Path" => refusal == Some(Refusal::Path),
        "Act" => refusal == Some(Refusal::Act),
        "RetainedActRefusal" => refusal == Some(Refusal::RetainedActRefusal),
        "Account" => refusal == Some(Refusal::Account),
        "Part" => refusal == Some(Refusal::Part),
        "Reference" => refusal == Some(Refusal::Reference),
        "Signature" => refusal == Some(Refusal::Signature),
        "ActorBinding" => refusal == Some(Refusal::ActorBinding),
        _ => panic!("unowned expected assessment {expected}"),
    }
}

fn expected_result<T: std::fmt::Debug>(actual: &Checked<T>, expected: &str) {
    assert!(matches_expected(actual, expected), "expected {expected}, got {actual:?}");
}

enum Actual {
    Codec(codec::FragmentError),
    Assessment(Checked<()>),
}

fn assert_actual(actual: &Actual, expected: &str, id: &str) {
    let matches = match actual {
        Actual::Assessment(value) => matches_expected(value, expected),
        Actual::Codec(value) => match expected {
            "Canonical" => *value == codec::FragmentError::Canonical,
            "Shape" => *value == codec::FragmentError::Shape,
            "Edition" => *value == codec::FragmentError::Edition,
            "Kind" => *value == codec::FragmentError::Kind,
            "Field" => *value == codec::FragmentError::Field,
            "Field(Edition)" => value == &codec::FragmentError::FieldWithNested(codec::NestedCause::Edition),
            "Field(Kind)" => value == &codec::FragmentError::FieldWithNested(codec::NestedCause::Kind),
            "Order" => *value == codec::FragmentError::Order,
            "Duplicate" => *value == codec::FragmentError::Duplicate,
            "UnavailableBudget" => *value == codec::FragmentError::UnavailableBudget,
            "MissingComponent" => *value == codec::FragmentError::MissingComponent,
            "UnsupportedEdition" => *value == codec::FragmentError::UnsupportedEdition,
            _ => panic!("unowned expected codec cause {expected}"),
        },
    };
    assert!(
        matches,
        "{id}: expected {expected}, got {}",
        match actual {
            Actual::Assessment(value) => format!("{value:?}"),
            Actual::Codec(value) => format!("{value:?}"),
        }
    );
}

fn representation_descriptors(
    site: &str,
    mut decode: impl FnMut(&[u8], &ReadAllowances) -> Result<(), codec::FragmentError>,
) -> Vec<String> {
    let cases = fixture();
    let selected = cases["executable_descriptors"].as_array().unwrap();
    let mut executed = Vec::new();
    for case in selected.iter().filter(|case| {
        case["site"] == site
            && (case["id"].as_str().unwrap().starts_with("byte:")
                || case["id"].as_str().unwrap().starts_with("allowance:")
                || (case["id"].as_str().unwrap().starts_with("new:")
                    && [
                        "-mistyped-edition",
                        "-missing-member",
                        "-extra-member",
                        "-member-length:",
                        "-member-range:",
                        "-nested-field:",
                        "-shape-before-",
                        "-budget-before-",
                        "-account-allowance",
                        "-kind-zero-null-unit",
                        "-kind-one-ref-unit",
                        "-part-layout",
                        "-association-layout",
                        "-nested-history-budget",
                        "-nested-account-blocks-budget",
                        "-nested-edition",
                        "-nested-kind",
                        "-nested-declaration-edition",
                        "-nested-account-edition",
                    ]
                    .iter()
                    .any(|suffix| case["id"].as_str().unwrap().contains(suffix))))
    }) {
        let input = decoded_hex(case["encoded"].as_str().unwrap());
        let mut limits = limits();
        if let Some(allowance) = case["allowance"].as_u64() {
            limits.encoded_bytes = usize::try_from(allowance).unwrap();
        }
        if let Some(allowance) = case["account_allowance"].as_u64() {
            limits.account_bytes = usize::try_from(allowance).unwrap();
        }
        if let Some(allowance) = case["history_scope_allowance"].as_u64() {
            limits.history_scope_bytes = usize::try_from(allowance).unwrap();
        }
        if let Some(allowance) = case["blocks_allowance"].as_u64() {
            limits.blocks = usize::try_from(allowance).unwrap();
        }
        let actual = decode(&input, &limits);
        let expected = case["expected"].as_str().unwrap();
        if expected == "BudgetAvailable" {
            assert!(actual.is_ok(), "{}: {actual:?}", case["id"]);
        } else {
            assert_actual(&Actual::Codec(actual.unwrap_err()), expected, case["id"].as_str().unwrap());
        }
        executed.push(case["id"].as_str().unwrap().to_owned());
    }
    let expected_count = match site {
        "account_order" => 27,
        "local_boundary_order" => 105,
        "local_declaration_order" => 43,
        "paper_boundary_order" => 71,
        "paper_declaration_order" => 54,
        _ => panic!("unowned representation site {site}"),
    };
    assert_eq!(executed.len(), expected_count, "representation descriptor set for {site}");
    executed
}

fn substitution_descriptors(site: &str) -> Vec<String> {
    let cases = fixture();
    let selected = cases["executable_descriptors"].as_array().unwrap();
    let mut executed = Vec::new();
    for case in selected
        .iter()
        .filter(|case| case["site"] == site && case["id"].as_str().unwrap().starts_with("substitution:"))
    {
        let name = case["evaluator_outcome"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let bytes = decoded_hex(case["encoded"].as_str().unwrap());
        let mut synthetic = Synthetic::from_fixture();
        let actual = match site {
            "paper_declaration_order" => Actual::Codec(codec::decode_paper_declaration(Some(&bytes), 2, &limits()).unwrap_err()),
            "paper_boundary_order" if name == "missing-paper-component" => {
                Actual::Codec(codec::decode_paper_boundary(None, 1, &limits()).unwrap_err())
            }
            "paper_boundary_order" => {
                synthetic.failure = Some("paper-unavailable");
                let value = codec::decode_paper_boundary(Some(&bytes), 1, &limits()).unwrap();
                synthetic.paper = value.clone();
                Actual::Assessment(pn_epoch::authentication::compare_paper_boundary(
                    &value,
                    Some(&synthetic.context),
                    &synthetic,
                ))
            }
            "account_order" => {
                synthetic.failure = Some(match name {
                    "no-evaluator" => "rules",
                    "unbound-account" | "prior-not-obtainable" => "binding-unavailable",
                    "bad-binding" => "binding",
                    "bad-link" | "bad-transaction-commitment" | "bad-signed-evidence" => "chain",
                    "missing-acquisition" => "chain-unavailable",
                    "missing-prior-epoch" => "missing-prior",
                    "present-wrong-prior-context" => "prior",
                    _ => panic!("unowned account substitution {name}"),
                });
                let value = codec::decode_account(Some(&bytes), 1, &limits()).unwrap();
                Actual::Assessment(pn_epoch::authentication::compare_authority_account(
                    &value,
                    Some(&synthetic.context),
                    &synthetic,
                ))
            }
            "local_boundary_order" if name == "annotation-only" => {
                Actual::Codec(codec::decode_local_boundary(None, 1, &limits()).unwrap_err())
            }
            "local_boundary_order" => {
                synthetic.failure = Some(match name {
                    "no-context" => "context",
                    "empty-active-set" | "valid-signature-unauthorized" => "membership",
                    "outside-covered-domain" => "not-covered",
                    "same-key-actor-swap" => "wrong-actor",
                    "changed-proposal" | "wrong-material" => "retained",
                    "bad-signature" | "bad-approval" => "signature",
                    _ => panic!("unowned local substitution {name}"),
                });
                let value = codec::decode_local_boundary(Some(&bytes), 1, &limits()).unwrap();
                let acts = fixture_acts(&value);
                Actual::Assessment(pn_epoch::authentication::compare_local_boundary(
                    &value,
                    &acts,
                    Some(&synthetic.context),
                    &synthetic,
                ))
            }
            _ => panic!("unowned substitution site {site}"),
        };
        assert_actual(&actual, expected, case["id"].as_str().unwrap());
        executed.push(case["id"].as_str().unwrap().to_owned());
    }
    let expected_count = match site {
        "paper_declaration_order" => 1,
        "paper_boundary_order" => 2,
        "account_order" | "local_boundary_order" => 10,
        _ => 0,
    };
    assert_eq!(executed.len(), expected_count, "substitution descriptor set for {site}");
    executed
}

fn semantic_actual(site: &str, bytes: &[u8], scenario: Option<&str>, synthetic: &mut Synthetic<'_>) -> Actual {
    match site {
        "paper_declaration_order" => {
            let value = codec::decode_paper_declaration(Some(bytes), 1, &limits()).unwrap();
            synthetic.paper.active = vec![value.clone()];
            Actual::Assessment(pn_epoch::authentication::compare_paper_declaration(
                &value,
                Some(&synthetic.context),
                synthetic,
            ))
        }
        "paper_boundary_order" => match codec::decode_paper_boundary(Some(bytes), 1, &limits()) {
            Err(error) => Actual::Codec(error),
            Ok(value) => {
                synthetic.paper = value.clone();
                Actual::Assessment(pn_epoch::authentication::compare_paper_boundary(
                    &value,
                    Some(&synthetic.context),
                    synthetic,
                ))
            }
        },
        "local_declaration_order" => {
            let value = codec::decode_local_declaration(Some(bytes), 1, &limits()).unwrap();
            Actual::Assessment(pn_epoch::authentication::compare_local_declaration(
                &value,
                Some(&synthetic.context),
                synthetic,
            ))
        }
        "account_order" => {
            let value = codec::decode_account(Some(bytes), 1, &limits()).unwrap();
            Actual::Assessment(pn_epoch::authentication::compare_authority_account(
                &value,
                Some(&synthetic.context),
                synthetic,
            ))
        }
        "local_boundary_order" => match codec::decode_local_boundary(Some(bytes), 1, &limits()) {
            Err(error) => Actual::Codec(error),
            Ok(value) => {
                if scenario == Some("prefix-overflow") {
                    synthetic.local.account.pin = value.account.pin.clone();
                }
                let acts = fixture_acts(&synthetic.local);
                Actual::Assessment(pn_epoch::authentication::compare_local_boundary(
                    &value,
                    &acts,
                    Some(&synthetic.context),
                    synthetic,
                ))
            }
        },
        _ => panic!("unowned semantic descriptor site {site}"),
    }
}

fn semantic_descriptors(site: &str) -> Vec<String> {
    let cases = fixture();
    let selected = cases["executable_descriptors"].as_array().unwrap();
    let mut executed = Vec::new();
    for case in selected.iter().filter(|case| {
        case["site"] == site
            && case["id"].as_str().unwrap().starts_with("new:")
            && ![
                "-mistyped-edition",
                "-missing-member",
                "-extra-member",
                "-member-length:",
                "-member-range:",
                "-nested-field:",
                "-shape-before-",
                "-budget-before-",
                "-account-allowance",
                "-kind-zero-null-unit",
                "-kind-one-ref-unit",
                "-part-layout",
                "-association-layout",
                "-nested-history-budget",
                "-nested-account-blocks-budget",
                "-nested-edition",
                "-nested-kind",
                "-nested-declaration-edition",
                "-nested-account-edition",
            ]
            .iter()
            .any(|suffix| case["id"].as_str().unwrap().contains(suffix))
    }) {
        let scenario = case["scenario"].as_str();
        let expected = case["expected"].as_str().unwrap();
        let bytes = decoded_hex(case["encoded"].as_str().unwrap());
        let mut synthetic = Synthetic::from_fixture();
        synthetic.failure = scenario;
        let actual = semantic_actual(site, &bytes, scenario, &mut synthetic);
        assert_actual(&actual, expected, case["id"].as_str().unwrap());
        executed.push(case["id"].as_str().unwrap().to_owned());
    }
    let expected_count = match site {
        "paper_declaration_order" => 5,
        "account_order" => 9,
        "paper_boundary_order" => 14,
        "local_declaration_order" => 6,
        "local_boundary_order" => 27,
        _ => 0,
    };
    assert_eq!(executed.len(), expected_count, "semantic descriptor set for {site}");
    executed
}

/// Claim: The admitted paper declaration mutations reach their first representation or contextual cause.
/// ´claim:publication:paper-declaration-order´
/// ´test:integration:paper-declaration-order´
#[test]
fn paper_declaration_order() {
    let mut executed = representation_descriptors("paper_declaration_order", |bytes, limits| {
        codec::decode_paper_declaration(Some(bytes), 1, limits).map(|_| ())
    });
    executed.extend(substitution_descriptors("paper_declaration_order"));
    executed.extend(semantic_descriptors("paper_declaration_order"));
    let mut synthetic = Synthetic::from_fixture();
    let base = codec::decode_paper_declaration(
        Some(&decoded_hex(row("provenance")["encoded"].as_str().unwrap())),
        1,
        &limits(),
    )
    .unwrap();
    synthetic.paper.active = vec![base];
    for name in [
        "wrong-kind",
        "changed-body-same-ref",
        "wrong-history",
        "edition-before-kind",
        "scope-not-in-force",
    ] {
        let case = row(name);
        let input = decoded_hex(case["encoded"].as_str().unwrap());
        let expected = case["expected"].as_str().unwrap();
        match codec::decode_paper_declaration(Some(&input), 1, &limits()) {
            Err(error) => assert_eq!(format!("{error:?}"), expected, "{name}"),
            Ok(value) => {
                if name == "scope-not-in-force" {
                    synthetic.paper.active = vec![value.clone()];
                }
                expected_result(
                    &pn_epoch::authentication::compare_paper_declaration(&value, Some(&synthetic.context), &synthetic),
                    expected,
                );
            }
        }
        executed.push(format!("row:{name}"));
    }
    assert_eq!(
        codec::decode_paper_declaration(Some(&[]), 2, &limits()).unwrap_err(),
        codec::FragmentError::UnsupportedEdition
    );
    assert_site_ids("paper_declaration_order", &executed);
}

/// Claim: Paper boundary representation order and selected predecessor deltas retain their first causes.
/// ´claim:publication:paper-boundary-order´
/// ´test:integration:paper-boundary-order´
#[test]
fn paper_boundary_order() {
    let mut executed = representation_descriptors("paper_boundary_order", |bytes, limits| {
        codec::decode_paper_boundary(Some(bytes), 1, limits).map(|_| ())
    });
    executed.extend(substitution_descriptors("paper_boundary_order"));
    executed.extend(semantic_descriptors("paper_boundary_order"));
    let mut synthetic = Synthetic::from_fixture();
    let old = codec::decode_paper_declaration(
        Some(&decoded_hex(row("provenance")["encoded"].as_str().unwrap())),
        1,
        &limits(),
    )
    .unwrap();
    synthetic.predecessor = vec![old];
    for name in [
        "omitted-withdrawal",
        "duplicate-withdrawal",
        "conflicting-change",
        "spurious-change",
        "successor-not-active",
        "order-before-duplicate",
        "descending-order",
    ] {
        let case = row(name);
        let input = decoded_hex(case["encoded"].as_str().unwrap());
        let expected = case["expected"].as_str().unwrap();
        match codec::decode_paper_boundary(Some(&input), 1, &limits()) {
            Err(error) => assert_eq!(format!("{error:?}"), expected, "{name}"),
            Ok(value) => {
                synthetic.paper = value.clone();
                // The independently selected predecessor contains the old declaration.
                let result = pn_epoch::authentication::compare_paper_boundary(&value, Some(&synthetic.context), &synthetic);
                expected_result(&result, expected);
            }
        }
        executed.push(format!("row:{name}"));
    }
    assert_site_ids("paper_boundary_order", &executed);
}

/// Claim: Local descriptor changes refuse at Declaration, Rules, Convention, Run or Scope in order.
/// ´claim:publication:local-declaration-order´
/// ´test:integration:local-declaration-order´
#[test]
fn local_declaration_order() {
    let mut executed = representation_descriptors("local_declaration_order", |bytes, limits| {
        codec::decode_local_declaration(Some(bytes), 1, limits).map(|_| ())
    });
    executed.extend(semantic_descriptors("local_declaration_order"));
    let synthetic = Synthetic::from_fixture();
    for name in [
        "declaration-before-rules",
        "declaration-scope-mismatch",
        "declaration-run-mismatch",
        "declaration-ref-mismatch",
        "declaration-convention-mismatch",
        "declaration-rules-mismatch",
    ] {
        let case = row(name);
        let value = codec::decode_local_declaration(Some(&decoded_hex(case["encoded"].as_str().unwrap())), 1, &limits()).unwrap();
        expected_result(
            &pn_epoch::authentication::compare_local_declaration(&value, Some(&synthetic.context), &synthetic),
            case["expected"].as_str().unwrap(),
        );
        executed.push(format!("row:{name}"));
    }
    assert_site_ids("local_declaration_order", &executed);
}

/// Claim: Independent account mutations retain `Prefix`, `Overflow`, `MissingEvidence` and `Coverage` order.
/// ´claim:publication:authority-account-order´
/// ´test:integration:account-order´
#[test]
fn account_order() {
    let mut executed = representation_descriptors("account_order", |bytes, limits| {
        codec::decode_account(Some(bytes), 1, limits).map(|_| ())
    });
    executed.extend(substitution_descriptors("account_order"));
    executed.extend(semantic_descriptors("account_order"));
    for name in [
        "prefix-before-overflow",
        "superfluous-first-height",
        "wrong-claimed-minimum",
        "wrong-first-height",
        "prefix-overflow",
        "omitted-last-block",
    ] {
        let case = row(name);
        let value = codec::decode_account(Some(&decoded_hex(case["encoded"].as_str().unwrap())), 1, &limits()).unwrap();
        let mut synthetic = Synthetic::from_fixture();
        if name == "prefix-overflow" {
            synthetic.local.account.pin = value.pin.clone();
        }
        expected_result(
            &pn_epoch::authentication::compare_authority_account(&value, Some(&synthetic.context), &synthetic),
            case["expected"].as_str().unwrap(),
        );
        executed.push(format!("row:{name}"));
    }
    assert_site_ids("account_order", &executed);
}

/// Claim: Local roster, association and scan-bound mutations retain their first selected cause.
/// ´claim:publication:local-boundary-order´
/// ´test:integration:local-boundary-order´
#[test]
fn local_boundary_order() {
    let mut executed = representation_descriptors("local_boundary_order", |bytes, limits| {
        codec::decode_local_boundary(Some(bytes), 1, limits).map(|_| ())
    });
    executed.extend(substitution_descriptors("local_boundary_order"));
    executed.extend(semantic_descriptors("local_boundary_order"));
    let baseline = Synthetic::from_fixture();
    let acts = fixture_acts(&baseline.local);
    let mut mismatches = Vec::new();
    for name in [
        "coverage-before-reference",
        "wrong-act-position",
        "wrong-discriminator",
        "old-act-associated",
        "transplanted-account",
        "out-of-range-part",
        "wrong-part",
        "buffer-scan",
        "too-early-scan",
        "too-late-scan",
    ] {
        let case = row(name);
        let input = decoded_hex(case["encoded"].as_str().unwrap());
        let expected = case["expected"].as_str().unwrap();
        let actual = match codec::decode_local_boundary(Some(&input), 1, &limits()) {
            Err(error) => Actual::Codec(error),
            Ok(value) => Actual::Assessment(pn_epoch::authentication::compare_local_boundary(
                &value,
                &acts,
                Some(&baseline.context),
                &baseline,
            )),
        };
        let agrees = match &actual {
            Actual::Codec(error) => matches!(error, codec::FragmentError::Shape) && expected == "Shape",
            Actual::Assessment(value) => matches_expected(value, expected),
        };
        if !agrees {
            mismatches.push(format!("{name}: expected {expected}"));
        }
        executed.push(format!("row:{name}"));
    }
    assert_site_ids("local_boundary_order", &executed);
    assert!(mismatches.is_empty(), "{}", mismatches.join("; "));
}

/// Claim: A separately selected current query checks covered membership and reports an uncovered Actor without changing an old pin.
/// ´claim:publication:current-authority-membership´
/// ´test:integration:current-authority-membership´
#[test]
fn current_authority_membership() {
    let mut synthetic = Synthetic::from_fixture();
    let boundary = synthetic.local.clone();
    let context = boundary.context.clone();
    let acts = fixture_acts(&boundary);
    let original_contexts = vec![context.clone(); acts.len()];
    let prior = (0..context.epoch)
        .map(|epoch| PriorRange {
            history_scope: boundary.account.prior_range.history_scope.clone(),
            first_epoch: epoch,
            exclusive_end: epoch + 1,
        })
        .collect::<Vec<_>>();
    let assess = |acts: &[ClosureAct<FixtureHeader>], originals: &[BoundaryContext], consumer: &Synthetic<'_>| {
        pn_epoch::authentication::evaluate_current_authority(
            CurrentAuthorityQuery {
                retained_acts: acts,
                original_pin_contexts: originals,
                selected_current_context: &context,
                selected_current_rules: &boundary.declaration,
                current_account_view: CurrentAccountView {
                    account: &boundary.account,
                    parts: &boundary.parts,
                },
                prior_epoch_views: &prior,
                read_allowances: limits(),
            },
            consumer,
        )
    };
    synthetic.failure = Some("membership");
    let changed = assess(&acts, &original_contexts, &synthetic);
    assert_eq!(changed.at_pin, PinDisposition::AtPinUnchanged);
    assert!(matches!(
        changed.current,
        Checked::Confirmed(Assessed { value, .. }) if value.len() == acts.len()
            && value.iter().all(|entry| matches!(entry.membership, Checked::RefusedWithPremises(Assessed { value: Refusal::ActorBinding, .. })))
    ));
    synthetic.failure = None;
    let mut foreign_header = acts[0].header().clone();
    foreign_header.id.author = "uncovered-actor".to_owned();
    let foreign = [ClosureAct::new(
        foreign_header,
        Vec::new(),
        [0; 64],
        [0; 64],
        context.epoch,
        0,
        0,
    )];
    let foreign_contexts = [context.clone()];
    let uncovered = assess(&foreign, &foreign_contexts, &synthetic);
    assert_eq!(uncovered.at_pin, PinDisposition::AtPinUnchanged);
    assert!(matches!(
        uncovered.current,
        Checked::UnavailableWithPremises(Assessed {
            value: Inability::NotCovered,
            ..
        })
    ));
}

/// Claim: Caller-selected component decoders refuse historical fragments, and historical decoders refuse each successor component.
/// ´claim:publication:boundary-component-isolation´
/// ´test:integration:historical-isolation´
#[test]
fn historical_isolation() {
    let carrier: Value = serde_json::from_str(include_str!("../../../act-authentication/tests/carrier-golden.json")).unwrap();
    let formation: Value = serde_json::from_str(include_str!("../../../act-authentication/tests/v3-golden.json")).unwrap();
    let old = decoded_hex(carrier["rows"][0]["closure"].as_str().unwrap());
    let header = decoded_hex(formation["rows"][0]["header"].as_str().unwrap());
    let fixture = fixture();
    let descriptor = fixture["executable_descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == "new:cross-feed-historical-formation-components")
        .unwrap();
    assert_eq!(descriptor["encoded"], row("provenance")["encoded"]);
    assert_eq!(descriptor["foreign_closure"], carrier["rows"][0]["closure"]);
    assert_eq!(descriptor["foreign_header"], formation["rows"][0]["header"]);
    for foreign in [&old, &header] {
        assert!(codec::decode_paper_declaration(Some(foreign), 1, &limits()).is_err());
        assert!(codec::decode_paper_boundary(Some(foreign), 1, &limits()).is_err());
        assert!(codec::decode_local_declaration(Some(foreign), 1, &limits()).is_err());
        assert!(codec::decode_account(Some(foreign), 1, &limits()).is_err());
        assert!(codec::decode_local_boundary(Some(foreign), 1, &limits()).is_err());
    }
    let families = fixture["classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    for (index, family) in families.iter().enumerate() {
        let row = rows(family).remove(0);
        let bytes = decoded_hex(row["encoded"].as_str().unwrap());
        assert!(
            pn_act_authentication::v3::decode_header(&bytes).is_err(),
            "{family} entered historical header"
        );
        assert!(
            pn_host::publication::closure::decode_proof(&bytes).is_err(),
            "{family} entered historical proof"
        );
        assert!(
            pn_host::publication::closure::decode_act(&bytes, [3; 32], "host").is_err(),
            "{family} entered historical act"
        );
        let mut numeric = pn_records::numerics::NumericContext::new(
            pn_epoch::publication::disclosures::limits::Limits::default(),
            pn_records::numerics::ComparisonLimits::new(1000, 1000),
        )
        .unwrap();
        assert!(
            pn_host::publication::decode(&bytes, &mut numeric, pn_epoch::publication::disclosures::Limits::default()).is_err(),
            "{family} entered historical publication"
        );
        if index != 0 {
            assert!(codec::decode_paper_declaration(Some(&bytes), 1, &limits()).is_err());
        }
        if index != 1 {
            assert!(codec::decode_paper_boundary(Some(&bytes), 1, &limits()).is_err());
        }
        if index != 2 {
            assert!(codec::decode_local_declaration(Some(&bytes), 1, &limits()).is_err());
        }
        if index != 3 {
            assert!(codec::decode_account(Some(&bytes), 1, &limits()).is_err());
        }
        if index != 4 {
            assert!(codec::decode_local_boundary(Some(&bytes), 1, &limits()).is_err());
        }
    }
    assert_site_ids(
        "historical_isolation",
        &["new:cross-feed-historical-formation-components".to_owned()],
    );
}
