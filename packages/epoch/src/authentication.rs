//! Conditional successor boundary assessment. Selection and evaluator results are explicit.
//! An equal component is not an authenticated publication or a production capability.
//! (´[ROOT-amend:identity:local-authority-boundary]´)

use pn_records::ActId;
use pn_records::cases::{ComponentRef, LocalAuthorityDeclaration, PaperCaseDeclaration};
use pn_records::closure::{ClosureAct, ClosureHeader};

/// The exact selected public context; history scope is retained as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryContext {
    pub run: [u8; 32],
    pub history_scope: Vec<u8>,
    pub epoch: u64,
}

/// A complete predecessor reference, never a filtered retirement set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorRange {
    pub history_scope: Vec<u8>,
    pub first_epoch: u64,
    pub exclusive_end: u64,
}

/// Independently supplied limits describe the reader's available work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadAllowances {
    pub encoded_bytes: usize,
    pub history_scope_bytes: usize,
    pub declarations: usize,
    pub transitions: usize,
    pub account_bytes: usize,
    pub blocks: usize,
    pub block_bytes: usize,
    pub parts: usize,
    pub associations: usize,
    pub prior_epochs: usize,
}

/// Successor or withdrawal of one independently selected paper case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaperChange {
    Successor { old: ComponentRef, new: ComponentRef },
    Withdrawal { old: ComponentRef },
}

impl PaperChange {
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            operation = "authentication-paper-change-old",
            source_item = "authentication::PaperChange::old"
        ),
        ret
    )]
    pub fn old(&self) -> &ComponentRef {
        match self {
            Self::Successor { old, .. } | Self::Withdrawal { old } => old,
        }
    }
}

/// Complete bound paper set, including an explicit empty set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaperCaseBoundary {
    pub context: BoundaryContext,
    pub active: Vec<PaperCaseDeclaration>,
    pub changes: Vec<PaperChange>,
}

/// Exact marker prefix and declared stability buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPin {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub buffer: u64,
}

/// Complete public blocks, not a supplier's assertion of active keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAccount {
    pub context: BoundaryContext,
    pub pin: AccountPin,
    pub run_configuration: Vec<u8>,
    pub chain_parameters: Vec<u8>,
    pub first_height: u64,
    pub blocks: Vec<Vec<u8>>,
    pub prior_range: PriorRange,
}

/// The qualified issuance location of one covered Actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceLocator {
    pub height: u64,
    pub transaction_index: u64,
    pub input_index: u64,
    pub issuance_prevout: [u8; 36],
}

/// One covered Actor's complete scan boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPart {
    pub actor: String,
    pub issuance: IssuanceLocator,
    pub scan_from: u64,
    pub scan_through: u64,
    pub prior_range: PriorRange,
}

/// Association with an exact retained act and one shared account part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActAssociation {
    pub context: BoundaryContext,
    pub act_position: u64,
    pub act: ActId,
    pub local_declaration: ComponentRef,
    pub account_context: BoundaryContext,
    pub account_index: u64,
    pub part_index: u64,
}

/// Required local extension, outside the paper case set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAuthorityBoundary {
    pub context: BoundaryContext,
    pub declaration: LocalAuthorityDeclaration,
    pub account: AuthorityAccount,
    pub parts: Vec<ActorPart>,
    pub associations: Vec<ActAssociation>,
}

/// Both independently selected component families are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryComponents {
    pub paper: PaperCaseBoundary,
    pub local: LocalAuthorityBoundary,
}

/// An explicit synthetic premise cannot establish production readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvaluatorSelection {
    ExplicitSyntheticPremise,
}

/// The independently selected consensus and complete-parent-binding premises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessmentPremises {
    pub evaluator: EvaluatorSelection,
    pub consensus: String,
    pub binding: String,
    pub context: BoundaryContext,
}

/// A positive result always keeps the premises under which it was assessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessed<T> {
    pub value: T,
    pub premises: AssessmentPremises,
}

/// Public, bounded refusal reasons. They do not contain instance secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Edition,
    Kind,
    Field,
    Order,
    Duplicate,
    Context,
    SelectionMismatch,
    DeclarationContent,
    Declaration,
    Rules,
    Convention,
    Run,
    Scope,
    CaseSet,
    Transition,
    FailedCase,
    Prefix,
    Overflow,
    MissingEvidence,
    Binding,
    Chain,
    History,
    Qualification,
    Actor,
    Coverage,
    Path,
    Act,
    RetainedActRefusal,
    Account,
    Part,
    Reference,
    Signature,
    ActorBinding,
}

/// Inability is distinct from a demonstrated defect of the supplied evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inability {
    MissingComponent,
    UnsupportedEdition,
    UnavailableBudget,
    UnavailableContext,
    UnavailableSelection,
    UnavailableDefinition,
    UnavailablePredecessor,
    UnavailableRules,
    UnavailableBinding,
    UnavailableEvaluation,
    UnavailableLinkage,
    NotCovered,
    NotEvaluated,
}

/// A confirmed value, refusal or inability, with assessed premises where established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checked<T> {
    Confirmed(Assessed<T>),
    Refused(Refusal),
    Unavailable(Inability),
    RefusedWithPremises(Assessed<Refusal>),
    UnavailableWithPremises(Assessed<Inability>),
}

/// Three separately selected boundaries and their conditional aggregate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryAssessment {
    pub closure: Checked<()>,
    pub local: Checked<()>,
    pub paper: Checked<()>,
    pub ready: Checked<()>,
}

/// The exact input to a pure component comparison, supplied by the caller.
#[derive(Debug)]
pub struct BoundaryView<'a, H: ClosureHeader> {
    pub paper: Option<&'a PaperCaseBoundary>,
    pub local: Option<&'a LocalAuthorityBoundary>,
    pub selected: Option<&'a BoundaryContext>,
    pub acts: &'a [ClosureAct<H>],
}

/// The producer keeps its complete public values beside, not inside, retained acts.
#[derive(Debug)]
pub struct BoundaryInput<'a, H: ClosureHeader> {
    pub components: BoundaryComponents,
    pub selected: Option<&'a BoundaryContext>,
    pub acts: &'a [ClosureAct<H>],
}

/// A failed or unevaluable comparison retains no assembled component object.
#[derive(Debug)]
pub struct BoundaryBuild {
    pub components: Option<BoundaryComponents>,
    pub assessment: BoundaryAssessment,
}

/// A checked authority set, with its full premise context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeysWithPremises {
    pub actor: String,
    pub keys: Vec<[u8; 32]>,
    pub pin: AccountPin,
}

/// Public identity extracted from a complete retained act by its selected reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedIdentity {
    pub actor: String,
    pub signer_key_hash: [u8; 32],
}

/// Independently selected current and predecessor declaration sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaperHistory {
    pub current: Vec<PaperCaseDeclaration>,
    pub predecessor: Option<Vec<PaperCaseDeclaration>>,
}

/// A required semantic consumer. Implementations must state each independent fact.
/// No method supplies a success, empty set or signature by default.
pub trait BoundaryConsumer: std::fmt::Debug {
    fn required_boundary_context(&self, candidate: &BoundaryContext) -> Checked<BoundaryContext>;
    fn paper_declaration_definition(&self, selected: &BoundaryContext, reference: &ComponentRef)
    -> Checked<PaperCaseDeclaration>;
    fn local_declaration_definition(&self, selected: &BoundaryContext) -> Checked<LocalAuthorityDeclaration>;
    fn paper_declaration_history(&self, candidate: &PaperCaseBoundary) -> Checked<PaperHistory>;
    fn prior_epoch(&self, candidate: &PriorRange) -> Checked<()>;
    fn compare_marker_prefix(&self, candidate: &AccountPin) -> Checked<()>;
    fn selected_chain_rules(&self, selected: &BoundaryContext) -> Checked<()>;
    fn compare_public_binding(&self, candidate: &AuthorityAccount) -> Checked<()>;
    fn evaluate_chain_evidence(&self, candidate: &AuthorityAccount) -> Checked<()>;
    fn qualified_first_height(&self, candidate: &AuthorityAccount) -> Checked<u64>;
    fn compare_retained_act<H: ClosureHeader>(&self, candidate: &ClosureAct<H>) -> Checked<RetainedIdentity>;
    fn verify_recorded_role<H: ClosureHeader>(&self, candidate: &ClosureAct<H>, role: Role) -> Checked<()>;
    fn authority_set(&self, account: &AuthorityAccount, part: &ActorPart) -> Checked<AuthorizedKeysWithPremises>;
    fn evaluate_case(&self, declaration: &PaperCaseDeclaration) -> Checked<()>;
}

/// Exact role to be verified over a complete retained act.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Proposal,
    Seal,
    Approval,
}

enum Failed {
    Refused(Refusal),
    Unavailable(Inability),
    RefusedWithPremises(Assessed<Refusal>),
    UnavailableWithPremises(Assessed<Inability>),
}

fn failed_checked(failed: &Failed) -> Checked<()> {
    match failed {
        Failed::Refused(cause) => Checked::Refused(*cause),
        Failed::Unavailable(reason) => Checked::Unavailable(*reason),
        Failed::RefusedWithPremises(value) => Checked::RefusedWithPremises(value.clone()),
        Failed::UnavailableWithPremises(value) => Checked::UnavailableWithPremises(value.clone()),
    }
}

fn forward<T>(outcome: Checked<T>) -> Result<Assessed<T>, Failed> {
    match outcome {
        Checked::Confirmed(value) => Ok(value),
        Checked::Refused(cause) => Err(Failed::Refused(cause)),
        Checked::Unavailable(reason) => Err(Failed::Unavailable(reason)),
        Checked::RefusedWithPremises(value) => Err(Failed::RefusedWithPremises(value)),
        Checked::UnavailableWithPremises(value) => Err(Failed::UnavailableWithPremises(value)),
    }
}

// A consumer cannot establish a refusal without saying which assessment made it.
fn forward_consumer<T>(outcome: Checked<T>) -> Result<Assessed<T>, Failed> {
    match outcome {
        Checked::Refused(_) => Err(Failed::Unavailable(Inability::UnavailableBinding)),
        other => forward(other),
    }
}

fn forward_consumer_under<T>(outcome: Checked<T>, expected: &AssessmentPremises) -> Result<Assessed<T>, Failed> {
    match &outcome {
        Checked::Confirmed(value) if !same_premises(&value.premises, expected) => {
            return Err(Failed::Unavailable(Inability::UnavailableBinding));
        }
        Checked::RefusedWithPremises(value) if !same_premises(&value.premises, expected) => {
            return Err(Failed::Unavailable(Inability::UnavailableBinding));
        }
        Checked::UnavailableWithPremises(value) if !same_premises(&value.premises, expected) => {
            return Err(Failed::Unavailable(Inability::UnavailableBinding));
        }
        _ => {}
    }
    forward_consumer(outcome)
}

fn with_premises<T>(outcome: Checked<T>, premises: &AssessmentPremises) -> Checked<T> {
    match outcome {
        Checked::Refused(cause) => Checked::RefusedWithPremises(Assessed {
            value: cause,
            premises: premises.clone(),
        }),
        Checked::Unavailable(reason) => Checked::UnavailableWithPremises(Assessed {
            value: reason,
            premises: premises.clone(),
        }),
        other => other,
    }
}

fn same_premises(left: &AssessmentPremises, right: &AssessmentPremises) -> bool {
    left == right
}

/// Compare a paper descriptor with independently selected complete content and scope.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-paper-declaration",
        source_item = "authentication::compare_paper_declaration"
    ),
    ret
)]
pub fn compare_paper_declaration(
    candidate: &PaperCaseDeclaration,
    selected: Option<&BoundaryContext>,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    let Some(selected) = selected else {
        return Checked::Unavailable(Inability::UnavailableContext);
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    let expected = match forward_consumer_under(
        consumer.paper_declaration_definition(selected, &candidate.reference),
        &context.premises,
    ) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if !same_premises(&context.premises, &expected.premises) {
        return with_premises(Checked::Unavailable(Inability::UnavailableBinding), &context.premises);
    }
    if candidate.scope.run != context.value.run || candidate.scope.history_scope != context.value.history_scope {
        return with_premises(Checked::Refused(Refusal::Context), &context.premises);
    }
    if *candidate != expected.value {
        return with_premises(Checked::Refused(Refusal::DeclarationContent), &expected.premises);
    }
    if candidate.scope.announced_at > candidate.scope.effective_at || candidate.scope.effective_at > selected.epoch {
        return with_premises(Checked::Refused(Refusal::Scope), &expected.premises);
    }
    Checked::Confirmed(Assessed {
        value: (),
        premises: expected.premises,
    })
}

/// Compare a local descriptor in Declaration, Rules, Convention, Run and Scope order.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-local-declaration",
        source_item = "authentication::compare_local_declaration"
    ),
    ret
)]
pub fn compare_local_declaration(
    candidate: &LocalAuthorityDeclaration,
    selected: Option<&BoundaryContext>,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    let Some(selected) = selected else {
        return Checked::Unavailable(Inability::UnavailableContext);
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    let expected = match forward_consumer_under(consumer.local_declaration_definition(selected), &context.premises) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if !same_premises(&context.premises, &expected.premises) {
        return with_premises(Checked::Unavailable(Inability::UnavailableBinding), &context.premises);
    }
    if candidate.scope.run != context.value.run || candidate.scope.history_scope != context.value.history_scope {
        return with_premises(Checked::Refused(Refusal::Context), &context.premises);
    }
    if candidate.reference != expected.value.reference
        || candidate.second_party != expected.value.second_party
        || candidate.genesis_hash != expected.value.genesis_hash
    {
        return with_premises(Checked::Refused(Refusal::Declaration), &expected.premises);
    }
    if candidate.rules != expected.value.rules {
        return with_premises(Checked::Refused(Refusal::Rules), &expected.premises);
    }
    if candidate.authorization_convention != expected.value.authorization_convention
        || candidate.projection != expected.value.projection
    {
        return with_premises(Checked::Refused(Refusal::Convention), &expected.premises);
    }
    if candidate.run_configuration != expected.value.run_configuration {
        return with_premises(Checked::Refused(Refusal::Run), &expected.premises);
    }
    if candidate.scope != expected.value.scope
        || candidate.scope.announced_at > candidate.scope.effective_at
        || candidate.scope.effective_at > selected.epoch
    {
        return with_premises(Checked::Refused(Refusal::Scope), &expected.premises);
    }
    Checked::Confirmed(Assessed {
        value: (),
        premises: expected.premises,
    })
}

/// Compare the paper set against selected content, predecessor and case evaluators.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-paper-boundary",
        source_item = "authentication::compare_paper_boundary"
    ),
    ret
)]
pub fn compare_paper_boundary(
    candidate: &PaperCaseBoundary,
    selected: Option<&BoundaryContext>,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    let Some(selected) = selected else {
        return Checked::Unavailable(Inability::UnavailableContext);
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if candidate.context != context.value {
        return with_premises(Checked::Refused(Refusal::Context), &context.premises);
    }
    with_premises(
        compare_paper(candidate, selected, consumer, &context.premises),
        &context.premises,
    )
}

/// Compare the complete supplied account with an independently selected prefix and evidence.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-authority-account",
        source_item = "authentication::compare_authority_account"
    ),
    ret
)]
pub fn compare_authority_account(
    candidate: &AuthorityAccount,
    selected: Option<&BoundaryContext>,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    let Some(selected) = selected else {
        return Checked::Unavailable(Inability::UnavailableContext);
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if candidate.context != context.value {
        return with_premises(Checked::Refused(Refusal::Context), &context.premises);
    }
    with_premises(
        match compare_account(candidate, consumer, &context.premises) {
            Ok(premises) if same_premises(&premises, &context.premises) => Checked::Confirmed(Assessed { value: (), premises }),
            Ok(_) => Checked::Unavailable(Inability::UnavailableBinding),
            Err(other) => failed_checked(&other),
        },
        &context.premises,
    )
}

/// Compare a required local component over complete retained acts and a selected context.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-local-boundary",
        source_item = "authentication::compare_local_boundary"
    ),
    ret
)]
pub fn compare_local_boundary<H: ClosureHeader>(
    candidate: &LocalAuthorityBoundary,
    acts: &[ClosureAct<H>],
    selected: Option<&BoundaryContext>,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    let Some(selected) = selected else {
        return Checked::Unavailable(Inability::UnavailableContext);
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if candidate.context != context.value {
        return with_premises(Checked::Refused(Refusal::Context), &context.premises);
    }
    with_premises(compare_local(candidate, acts, selected, consumer), &context.premises)
}

/// Compare the three conditional slots without selecting a production evaluator.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-compare-boundary",
        source_item = "authentication::compare_boundary"
    ),
    ret
)]
pub fn compare_boundary<H: ClosureHeader>(input: BoundaryView<'_, H>, consumer: &impl BoundaryConsumer) -> BoundaryAssessment {
    let unavailable = || Checked::Unavailable(Inability::NotEvaluated);
    let Some(selected) = input.selected else {
        return BoundaryAssessment {
            closure: unavailable(),
            local: Checked::Unavailable(Inability::UnavailableContext),
            paper: unavailable(),
            ready: unavailable(),
        };
    };
    let context = match forward_consumer(consumer.required_boundary_context(selected)) {
        Ok(value) => value,
        Err(other) => {
            let other: Checked<()> = failed_checked(&other);
            return BoundaryAssessment {
                closure: other.clone(),
                local: other.clone(),
                paper: other.clone(),
                ready: other,
            };
        }
    };
    if context.value != *selected {
        return BoundaryAssessment {
            closure: unavailable(),
            local: with_premises(Checked::Refused(Refusal::Context), &context.premises),
            paper: with_premises(Checked::Refused(Refusal::Context), &context.premises),
            ready: unavailable(),
        };
    }
    let closure = input.acts.iter().fold(
        Checked::Confirmed(Assessed {
            value: (),
            premises: context.premises.clone(),
        }),
        |previous, act| {
            if !matches!(previous, Checked::Confirmed(_)) {
                return previous;
            }
            let mut latest = None;
            for role in [Role::Proposal, Role::Seal, Role::Approval] {
                match forward_consumer_under(consumer.verify_recorded_role(act, role), &context.premises) {
                    Ok(value) if value.premises == context.premises => latest = Some(value.premises),
                    Ok(_) => {
                        return with_premises(Checked::Unavailable(Inability::UnavailableBinding), &context.premises);
                    }
                    Err(other) => return failed_checked(&other),
                }
            }
            Checked::Confirmed(Assessed {
                value: (),
                premises: latest.unwrap_or_else(|| context.premises.clone()),
            })
        },
    );
    let closure = match closure {
        Checked::Unavailable(Inability::UnavailableBinding) => {
            with_premises(Checked::Unavailable(Inability::UnavailableBinding), &context.premises)
        }
        other => other,
    };
    let local = input
        .local
        .map_or(Checked::Unavailable(Inability::MissingComponent), |value| {
            compare_local_boundary(value, input.acts, Some(selected), consumer)
        });
    let paper = input
        .paper
        .map_or(Checked::Unavailable(Inability::MissingComponent), |value| {
            compare_paper_boundary(value, Some(selected), consumer)
        });
    // C8 has no admitted production evaluator; only C8E may add that route.
    let ready = Checked::Unavailable(Inability::NotEvaluated);
    BoundaryAssessment {
        closure,
        local,
        paper,
        ready,
    }
}

/// Construct the public components only when each conditional comparison succeeds.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        operation = "authentication-assemble-boundary",
        source_item = "authentication::assemble_boundary"
    ),
    ret
)]
pub fn assemble_boundary<H: ClosureHeader>(input: BoundaryInput<'_, H>, consumer: &impl BoundaryConsumer) -> BoundaryBuild {
    let assessment = compare_boundary(
        BoundaryView {
            paper: Some(&input.components.paper),
            local: Some(&input.components.local),
            selected: input.selected,
            acts: input.acts,
        },
        consumer,
    );
    let components = match (&assessment.closure, &assessment.local, &assessment.paper) {
        (Checked::Confirmed(closure), Checked::Confirmed(local), Checked::Confirmed(paper))
            if same_premises(&closure.premises, &local.premises) && same_premises(&closure.premises, &paper.premises) =>
        {
            Some(input.components)
        }
        _ => None,
    };
    BoundaryBuild { components, assessment }
}

fn compare_paper(
    value: &PaperCaseBoundary,
    selected: &BoundaryContext,
    consumer: &impl BoundaryConsumer,
    context_premises: &AssessmentPremises,
) -> Checked<()> {
    if value.context != *selected {
        return Checked::Refused(Refusal::Context);
    }
    for pair in value.active.windows(2) {
        if pair[0].reference > pair[1].reference {
            return Checked::Refused(Refusal::Order);
        }
    }
    for pair in value.active.windows(2) {
        if pair[0].reference == pair[1].reference {
            return Checked::Refused(Refusal::Duplicate);
        }
    }
    for pair in value.changes.windows(2) {
        if pair[0].old() > pair[1].old() {
            return Checked::Refused(Refusal::Order);
        }
    }
    for pair in value.changes.windows(2) {
        if pair[0].old() == pair[1].old() {
            return Checked::Refused(Refusal::Duplicate);
        }
    }
    for declaration in &value.active {
        let expected = match forward_consumer_under(
            consumer.paper_declaration_definition(selected, &declaration.reference),
            context_premises,
        ) {
            Ok(value) => value,
            Err(other) => return failed_checked(&other),
        };
        if !same_premises(&expected.premises, context_premises) {
            return Checked::Unavailable(Inability::UnavailableBinding);
        }
        if expected.value != *declaration {
            return Checked::Refused(Refusal::DeclarationContent);
        }
    }
    for declaration in &value.active {
        if declaration.scope.announced_at > declaration.scope.effective_at || declaration.scope.effective_at > selected.epoch {
            return Checked::Refused(Refusal::Scope);
        }
    }
    let expected = match forward_consumer_under(consumer.paper_declaration_history(value), context_premises) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if !same_premises(&expected.premises, context_premises) {
        return Checked::Unavailable(Inability::UnavailableBinding);
    }
    if value.active != expected.value.current {
        return Checked::Refused(Refusal::CaseSet);
    }
    let Some(predecessor) = &expected.value.predecessor else {
        return Checked::Unavailable(Inability::UnavailablePredecessor);
    };
    let ceased = predecessor
        .iter()
        .filter(|old| !value.active.iter().any(|new| new.reference == old.reference));
    if ceased.count() != value.changes.len() {
        return Checked::Refused(Refusal::Transition);
    }
    for change in &value.changes {
        let Some(old) = predecessor.iter().find(|old| old.reference == *change.old()) else {
            return Checked::Refused(Refusal::Transition);
        };
        if value.active.iter().any(|new| new.reference == old.reference) {
            return Checked::Refused(Refusal::Transition);
        }
        if let PaperChange::Successor { new, .. } = change {
            let Some(next) = value.active.iter().find(|declaration| declaration.reference == *new) else {
                return Checked::Refused(Refusal::Transition);
            };
            if next.kind != old.kind || next.scope.effective_at != selected.epoch {
                return Checked::Refused(Refusal::Transition);
            }
        }
    }
    for declaration in &value.active {
        match forward_consumer_under(consumer.evaluate_case(declaration), context_premises) {
            Ok(result) if same_premises(&result.premises, &expected.premises) => {}
            Ok(_) => return Checked::Unavailable(Inability::UnavailableBinding),
            Err(other) => return failed_checked(&other),
        }
    }
    Checked::Confirmed(Assessed {
        value: (),
        premises: expected.premises,
    })
}

fn check_local_roster<H: ClosureHeader>(value: &LocalAuthorityBoundary, acts: &[ClosureAct<H>]) -> Result<(), Refusal> {
    if value.associations.len() != acts.len() {
        return Err(Refusal::Coverage);
    }
    let roster = acts
        .iter()
        .map(|act| act.header().id().author.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let domain = value
        .parts
        .iter()
        .map(|part| part.actor.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if domain != roster || value.parts.len() != domain.len() {
        return Err(Refusal::Coverage);
    }
    for association in &value.associations {
        if association.account_index != 0
            || usize::try_from(association.part_index)
                .ok()
                .and_then(|index| value.parts.get(index))
                .is_none()
        {
            return Err(Refusal::Reference);
        }
    }
    Ok(())
}

fn compare_local<H: ClosureHeader>(
    value: &LocalAuthorityBoundary,
    acts: &[ClosureAct<H>],
    selected: &BoundaryContext,
    consumer: &impl BoundaryConsumer,
) -> Checked<()> {
    if value.context != *selected || value.account.context != *selected {
        return Checked::Refused(Refusal::Context);
    }
    if value.declaration.scope.run != selected.run || value.declaration.scope.history_scope != selected.history_scope {
        return Checked::Refused(Refusal::Context);
    }
    let declaration = match forward(compare_local_declaration(&value.declaration, Some(selected), consumer)) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if value.account.run_configuration != value.declaration.run_configuration {
        return Checked::Refused(Refusal::Run);
    }
    let prefix = match forward_consumer_under(consumer.compare_marker_prefix(&value.account.pin), &declaration.premises) {
        Ok(value) => value,
        Err(other) => return failed_checked(&other),
    };
    if !same_premises(&declaration.premises, &prefix.premises) {
        return Checked::Unavailable(Inability::UnavailableBinding);
    }
    if value.account.pin.height.checked_add(value.account.pin.buffer).is_none() {
        return Checked::Refused(Refusal::Overflow);
    }
    if let Err(cause) = check_local_roster(value, acts) {
        return Checked::Refused(cause);
    }
    let mut retained = Vec::with_capacity(acts.len());
    for act in acts {
        retained.push(
            match forward_consumer_under(consumer.compare_retained_act(act), &declaration.premises) {
                Ok(value) if same_premises(&declaration.premises, &value.premises) => value,
                Ok(_) => return Checked::Unavailable(Inability::UnavailableBinding),
                Err(other) => return failed_checked(&other),
            },
        );
    }
    let account_premises = match compare_account(&value.account, consumer, &declaration.premises) {
        Ok(premises) => premises,
        Err(other) => return failed_checked(&other),
    };
    if !same_premises(&declaration.premises, &account_premises) {
        return Checked::Unavailable(Inability::UnavailableBinding);
    }
    for part in &value.parts {
        if part.scan_from != part.issuance.height
            || part.scan_through != value.account.pin.height
            || part.prior_range != value.account.prior_range
        {
            return Checked::Refused(Refusal::Coverage);
        }
    }
    for ((association, act), identity) in value.associations.iter().zip(acts).zip(&retained) {
        if association.act != *act.header().id() || association.act_position != act.position() {
            return Checked::Refused(Refusal::Act);
        }
        if association.act.author != identity.value.actor {
            return Checked::Refused(Refusal::Actor);
        }
        if association.context != *selected || association.account_context != *selected {
            return Checked::Refused(Refusal::Account);
        }
        let part = &value.parts[usize::try_from(association.part_index).unwrap_or(0)];
        if part.actor != identity.value.actor || association.local_declaration != value.declaration.reference {
            return Checked::Refused(Refusal::Part);
        }
        for role in [Role::Proposal, Role::Approval] {
            match forward_consumer_under(consumer.verify_recorded_role(act, role), &declaration.premises) {
                Ok(result) if same_premises(&result.premises, &declaration.premises) => {}
                Ok(_) => return Checked::Unavailable(Inability::UnavailableBinding),
                Err(other) => return failed_checked(&other),
            }
        }
        let keys = match forward_consumer_under(consumer.authority_set(&value.account, part), &declaration.premises) {
            Ok(value) => value,
            Err(other) => return failed_checked(&other),
        };
        if !same_premises(&keys.premises, &declaration.premises) {
            return Checked::Unavailable(Inability::UnavailableBinding);
        }
        if keys.value.actor != part.actor || !keys.value.keys.contains(&identity.value.signer_key_hash) {
            return Checked::Refused(Refusal::ActorBinding);
        }
    }
    Checked::Confirmed(Assessed {
        value: (),
        premises: declaration.premises,
    })
}

fn compare_account(
    value: &AuthorityAccount,
    consumer: &impl BoundaryConsumer,
    expected: &AssessmentPremises,
) -> Result<AssessmentPremises, Failed> {
    let prefix = forward_consumer_under(consumer.compare_marker_prefix(&value.pin), expected)?;
    let Some(last) = value.pin.height.checked_add(value.pin.buffer) else {
        return Err(Failed::Refused(Refusal::Overflow));
    };
    let Some(count) = last.checked_sub(value.first_height).and_then(|n| n.checked_add(1)) else {
        return Err(Failed::Refused(Refusal::Overflow));
    };
    if usize::try_from(count).ok() != Some(value.blocks.len()) {
        return Err(Failed::Refused(Refusal::MissingEvidence));
    }
    let rules = forward_consumer_under(consumer.selected_chain_rules(&value.context), expected)?;
    if !same_premises(&prefix.premises, &rules.premises) {
        return Err(Failed::Unavailable(Inability::UnavailableBinding));
    }
    let bound = forward_consumer_under(consumer.compare_public_binding(value), expected)?;
    if !same_premises(&prefix.premises, &bound.premises) {
        return Err(Failed::Unavailable(Inability::UnavailableBinding));
    }
    let chain = forward_consumer_under(consumer.evaluate_chain_evidence(value), expected)?;
    if !same_premises(&prefix.premises, &chain.premises) {
        return Err(Failed::Unavailable(Inability::UnavailableBinding));
    }
    let prior = forward_consumer_under(consumer.prior_epoch(&value.prior_range), expected)?;
    if !same_premises(&prefix.premises, &prior.premises) {
        return Err(Failed::Unavailable(Inability::UnavailableBinding));
    }
    let minimum = forward_consumer_under(consumer.qualified_first_height(value), expected)?;
    if !same_premises(&prefix.premises, &minimum.premises) {
        return Err(Failed::Unavailable(Inability::UnavailableBinding));
    }
    if value.first_height > minimum.value {
        return Err(Failed::Refused(Refusal::MissingEvidence));
    }
    if value.first_height < minimum.value {
        return Err(Failed::Refused(Refusal::Coverage));
    }
    Ok(prefix.premises)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pn_records::PublicReference;
    use pn_records::StructuralBody;
    use pn_records::closure::ClosureLeg;
    use pn_records::commitments::ActCommitments;

    #[derive(Clone, Debug)]
    struct NoAct;

    impl ClosureHeader for NoAct {
        fn bytes(&self) -> &[u8] {
            unreachable!()
        }
        fn id(&self) -> &ActId {
            unreachable!()
        }
        fn body(&self) -> &StructuralBody {
            unreachable!()
        }
        fn legs(&self) -> Vec<ClosureLeg<'_>> {
            unreachable!()
        }
        fn protocol_references(&self) -> &[PublicReference] {
            unreachable!()
        }
        fn commitments(&self) -> &ActCommitments {
            unreachable!()
        }
    }

    #[derive(Debug)]
    struct Synthetic {
        context: BoundaryContext,
        local: LocalAuthorityDeclaration,
        paper: PaperHistory,
        alternate_paper_premise: bool,
    }

    impl Synthetic {
        fn positive<T>(&self, value: T, alternate: bool) -> Checked<T> {
            Checked::Confirmed(Assessed {
                value,
                premises: AssessmentPremises {
                    evaluator: EvaluatorSelection::ExplicitSyntheticPremise,
                    consensus: if alternate { "alternate" } else { "selected-consensus" }.to_owned(),
                    binding: "selected-complete-record".to_owned(),
                    context: self.context.clone(),
                },
            })
        }
    }

    impl BoundaryConsumer for Synthetic {
        fn required_boundary_context(&self, _candidate: &BoundaryContext) -> Checked<BoundaryContext> {
            self.positive(self.context.clone(), false)
        }
        fn paper_declaration_definition(
            &self,
            _selected: &BoundaryContext,
            reference: &ComponentRef,
        ) -> Checked<PaperCaseDeclaration> {
            self.paper
                .current
                .iter()
                .find(|candidate| &candidate.reference == reference)
                .map_or(Checked::Unavailable(Inability::UnavailableSelection), |value| {
                    self.positive(value.clone(), self.alternate_paper_premise)
                })
        }
        fn local_declaration_definition(&self, _selected: &BoundaryContext) -> Checked<LocalAuthorityDeclaration> {
            self.positive(self.local.clone(), false)
        }
        fn paper_declaration_history(&self, _candidate: &PaperCaseBoundary) -> Checked<PaperHistory> {
            self.positive(self.paper.clone(), self.alternate_paper_premise)
        }
        fn prior_epoch(&self, _candidate: &PriorRange) -> Checked<()> {
            self.positive((), false)
        }
        fn compare_marker_prefix(&self, _candidate: &AccountPin) -> Checked<()> {
            self.positive((), false)
        }
        fn selected_chain_rules(&self, _selected: &BoundaryContext) -> Checked<()> {
            self.positive((), false)
        }
        fn compare_public_binding(&self, _candidate: &AuthorityAccount) -> Checked<()> {
            self.positive((), false)
        }
        fn evaluate_chain_evidence(&self, _candidate: &AuthorityAccount) -> Checked<()> {
            self.positive((), false)
        }
        fn qualified_first_height(&self, candidate: &AuthorityAccount) -> Checked<u64> {
            self.positive(candidate.first_height, false)
        }
        fn compare_retained_act<H: ClosureHeader>(&self, _candidate: &ClosureAct<H>) -> Checked<RetainedIdentity> {
            unreachable!()
        }
        fn verify_recorded_role<H: ClosureHeader>(&self, _candidate: &ClosureAct<H>, _role: Role) -> Checked<()> {
            unreachable!()
        }
        fn authority_set(&self, _account: &AuthorityAccount, _part: &ActorPart) -> Checked<AuthorizedKeysWithPremises> {
            unreachable!()
        }
        fn evaluate_case(&self, _declaration: &PaperCaseDeclaration) -> Checked<()> {
            self.positive((), self.alternate_paper_premise)
        }
    }

    fn context() -> BoundaryContext {
        BoundaryContext {
            run: [3; 32],
            history_scope: vec![128],
            epoch: 3,
        }
    }

    fn reference(name: &str) -> ComponentRef {
        ComponentRef {
            namespace: "org.peer-network.test.fixture".to_owned(),
            name: name.to_owned(),
            edition: 1,
        }
    }

    fn declaration(context: &BoundaryContext) -> LocalAuthorityDeclaration {
        LocalAuthorityDeclaration {
            reference: ComponentRef {
                namespace: "org.peer-network.test.authority".to_owned(),
                name: "author-token".to_owned(),
                edition: 1,
            },
            scope: pn_records::cases::CaseScope {
                run: context.run,
                history_scope: context.history_scope.clone(),
                announced_at: 0,
                effective_at: 0,
            },
            second_party: reference("chain"),
            genesis_hash: [4; 32],
            rules: reference("rules"),
            authorization_convention: reference("convention"),
            projection: reference("projection"),
            run_configuration: vec![128],
        }
    }

    fn components(context: &BoundaryContext) -> BoundaryComponents {
        let prior = PriorRange {
            history_scope: context.history_scope.clone(),
            first_epoch: 0,
            exclusive_end: context.epoch,
        };
        BoundaryComponents {
            paper: PaperCaseBoundary {
                context: context.clone(),
                active: Vec::new(),
                changes: Vec::new(),
            },
            local: LocalAuthorityBoundary {
                context: context.clone(),
                declaration: declaration(context),
                account: AuthorityAccount {
                    context: context.clone(),
                    pin: AccountPin {
                        height: 8,
                        block_hash: [5; 32],
                        buffer: 2,
                    },
                    run_configuration: vec![128],
                    chain_parameters: vec![128],
                    first_height: 8,
                    blocks: vec![vec![128]; 3],
                    prior_range: prior,
                },
                parts: Vec::new(),
                associations: Vec::new(),
            },
        }
    }

    fn assert_site_ids(mut executed: Vec<&str>, mut expected: Vec<&str>) {
        executed.sort_unstable();
        expected.sort_unstable();
        assert_eq!(executed, expected);
    }

    /// Claim: An explicit empty paper set is compared with selected history, and a ceased case needs its transition.
    /// ´claim:admission:verification-case-context´
    /// ´test:unit:verification-case-context´
    #[test]
    fn verification_case_context() {
        let mut executed = Vec::new();
        let context = context();
        let components = components(&context);
        let consumer = Synthetic {
            context: context.clone(),
            local: components.local.declaration.clone(),
            paper: PaperHistory {
                current: Vec::new(),
                predecessor: Some(Vec::new()),
            },
            alternate_paper_premise: false,
        };
        assert!(matches!(
            compare_paper_boundary(&components.paper, Some(&context), &consumer),
            Checked::Confirmed(_)
        ));
        let mut ceased = consumer;
        ceased.paper.predecessor = Some(vec![PaperCaseDeclaration {
            reference: reference("old"),
            kind: pn_records::cases::PaperCaseKind::AuthorAuthority,
            scope: pn_records::cases::CaseScope {
                run: context.run,
                history_scope: context.history_scope.clone(),
                announced_at: 0,
                effective_at: 0,
            },
            second_party: reference("party"),
            rules: reference("rules"),
            convention: reference("convention"),
            projection: reference("projection"),
            published_data_rule: reference("data"),
            unit: None,
        }]);
        assert!(matches!(
            compare_paper_boundary(&components.paper, Some(&context), &ceased),
            Checked::RefusedWithPremises(Assessed {
                value: Refusal::Transition,
                ..
            })
        ));
        let mut withdrawn = components.paper;
        withdrawn.changes.push(PaperChange::Withdrawal { old: reference("old") });
        assert!(matches!(
            compare_paper_boundary(&withdrawn, Some(&context), &ceased),
            Checked::Confirmed(_)
        ));
        executed.push("new:explicit-empty-paper-and-transitions");
        assert_site_ids(executed, vec!["new:explicit-empty-paper-and-transitions"]);
    }

    /// Claim: Positive results retain evaluator and binding premises, and incompatible or synthetic premises never become production readiness.
    /// ´claim:admission:authority-outcome-mapping´
    /// ´test:unit:outcome-mapping´
    #[test]
    fn outcome_mapping() {
        let mut executed = Vec::new();
        let context = context();
        let components = components(&context);
        let mut consumer = Synthetic {
            context: context.clone(),
            local: components.local.declaration.clone(),
            paper: PaperHistory {
                current: Vec::new(),
                predecessor: Some(Vec::new()),
            },
            alternate_paper_premise: false,
        };
        let acts: &[ClosureAct<NoAct>] = &[];
        let view = |consumer: &Synthetic| {
            compare_boundary(
                BoundaryView {
                    paper: Some(&components.paper),
                    local: Some(&components.local),
                    selected: Some(&context),
                    acts,
                },
                consumer,
            )
        };
        let same = view(&consumer);
        assert!(matches!(same.local, Checked::Confirmed(_)));
        assert!(matches!(same.paper, Checked::Confirmed(_)));
        if let Checked::Confirmed(local) = &same.local {
            assert_eq!(local.premises.evaluator, EvaluatorSelection::ExplicitSyntheticPremise);
            assert_eq!(local.premises.binding, "selected-complete-record");
            assert_eq!(local.premises.context, context);
        }
        assert_eq!(same.ready, Checked::Unavailable(Inability::NotEvaluated));
        let unbound: Result<Assessed<()>, Failed> = forward_consumer(Checked::Refused(Refusal::Signature));
        assert!(matches!(unbound, Err(Failed::Unavailable(Inability::UnavailableBinding))));
        consumer.context.epoch += 1;
        let wrong_context = view(&consumer);
        assert!(matches!(
            wrong_context.local,
            Checked::RefusedWithPremises(Assessed {
                value: Refusal::Context,
                ..
            })
        ));
        assert!(matches!(
            wrong_context.paper,
            Checked::RefusedWithPremises(Assessed {
                value: Refusal::Context,
                ..
            })
        ));
        consumer.context.epoch -= 1;
        executed.push("new:positive-premise-retention");
        let mut misplaced = components.local.clone();
        misplaced.context.epoch += 1;
        let refusal = compare_local_boundary(&misplaced, acts, Some(&context), &consumer);
        assert!(matches!(
            refusal,
            Checked::RefusedWithPremises(Assessed {
                value: Refusal::Context,
                premises: AssessmentPremises { binding, .. },
            }) if binding == "selected-complete-record"
        ));
        consumer.alternate_paper_premise = true;
        let mixed = view(&consumer);
        assert!(matches!(mixed.local, Checked::Confirmed(_)));
        assert!(matches!(
            mixed.paper,
            Checked::UnavailableWithPremises(Assessed {
                value: Inability::UnavailableBinding,
                ..
            })
        ));
        assert_eq!(mixed.ready, Checked::Unavailable(Inability::NotEvaluated));
        executed.push("new:incompatible-premise-aggregate");
        assert_site_ids(
            executed,
            vec!["new:positive-premise-retention", "new:incompatible-premise-aggregate"],
        );
    }

    /// Claim: A required local component cannot be supplied by an explicit empty paper set.
    /// ´claim:admission:mandatory-authority-context´
    /// ´test:unit:missing-authority-case´
    #[test]
    fn missing_authority_case() {
        let mut executed = Vec::new();
        let context = context();
        let components = components(&context);
        let consumer = Synthetic {
            context: context.clone(),
            local: components.local.declaration.clone(),
            paper: PaperHistory {
                current: Vec::new(),
                predecessor: Some(Vec::new()),
            },
            alternate_paper_premise: false,
        };
        let acts: &[ClosureAct<NoAct>] = &[];
        let result = compare_boundary(
            BoundaryView {
                paper: Some(&components.paper),
                local: None,
                selected: Some(&context),
                acts,
            },
            &consumer,
        );
        assert!(matches!(result.paper, Checked::Confirmed(_)));
        assert_eq!(result.local, Checked::Unavailable(Inability::MissingComponent));
        assert_eq!(result.ready, Checked::Unavailable(Inability::NotEvaluated));
        executed.push("new:absent-required-local-with-empty-paper");
        let supplied = compare_boundary(
            BoundaryView {
                paper: Some(&components.paper),
                local: Some(&components.local),
                selected: Some(&context),
                acts,
            },
            &consumer,
        );
        assert!(matches!(supplied.local, Checked::Confirmed(_)));
        assert!(matches!(supplied.paper, Checked::Confirmed(_)));
        executed.push("substitution:no-courtesy");
        assert_site_ids(
            executed,
            vec!["substitution:no-courtesy", "new:absent-required-local-with-empty-paper"],
        );
    }
}
