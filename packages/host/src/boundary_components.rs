//! Five separately selected public successor fragments. Historical publication is unchanged.
//! Decoding checks representation; it does not authenticate a component's selection.
//! (´[ROOT-amend:identity:paper-case-declaration]´)

use pn_act_profile::v3::valid_act_id;
use pn_epoch::authentication::{
    AccountPin, ActAssociation, ActorPart, AuthorityAccount, BoundaryContext, IssuanceLocator, LocalAuthorityBoundary,
    PaperCaseBoundary, PaperChange, PriorRange, ReadAllowances,
};
use pn_interchange::{Array, Bytes, Value};
use pn_records::ActId;
use pn_records::cases::{CaseScope, ComponentRef, LocalAuthorityDeclaration, PaperCaseDeclaration, PaperCaseKind};

/// The ordered representation outcome for a standalone component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentError {
    UnsupportedEdition,
    MissingComponent,
    UnavailableBudget,
    Canonical,
    Shape,
    Edition,
    Kind,
    Field,
    /// A nested component's own edition or kind refused during this boundary's Field stage.
    FieldWithNested(NestedCause),
    Order,
    Duplicate,
}

/// The closed causes a nested component can expose through a boundary Field refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedCause {
    Edition,
    Kind,
}

fn nested_component(cause: FragmentError) -> FragmentError {
    match cause {
        FragmentError::Edition => FragmentError::FieldWithNested(NestedCause::Edition),
        FragmentError::Kind => FragmentError::FieldWithNested(NestedCause::Kind),
        FragmentError::Field => FragmentError::Field,
        other => other,
    }
}

impl std::fmt::Display for FragmentError {
    #[doc = "Justified: Formatting a bounded public error is inherited by its instrumented codec operation; a span here could recurse while recording that error."]
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FragmentError {}

fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(Bytes::from(value.to_vec()))
}

fn items(value: &Value) -> Result<&[Value], FragmentError> {
    match value {
        Value::Array(items) => Ok(items.as_slice()),
        _ => Err(FragmentError::Shape),
    }
}

fn members<const N: usize>(value: &Value) -> Result<&[Value; N], FragmentError> {
    items(value)?.try_into().map_err(|_| FragmentError::Shape)
}

fn unsigned(value: &Value) -> Result<u64, FragmentError> {
    match value {
        Value::Unsigned(number) => Ok(*number),
        _ => Err(FragmentError::Shape),
    }
}

fn octets(value: &Value) -> Result<&[u8], FragmentError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.as_slice()),
        _ => Err(FragmentError::Shape),
    }
}

fn string(value: &Value) -> Result<&str, FragmentError> {
    match value {
        Value::Text(text) => Ok(text.as_str()),
        _ => Err(FragmentError::Shape),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], FragmentError> {
    octets(value)?.try_into().map_err(|_| FragmentError::Shape)
}

// Shape is a complete pass over the selected value. Semantic field checks below
// may therefore never hide a later malformed member of the same component.
fn shape_ref(value: &Value) -> Result<(), FragmentError> {
    let [namespace, name, edition] = members(value)?;
    string(namespace)?;
    string(name)?;
    unsigned(edition)?;
    Ok(())
}

fn shape_context(value: &Value) -> Result<(), FragmentError> {
    let [run, scope, epoch] = members(value)?;
    fixed::<32>(run)?;
    octets(scope)?;
    unsigned(epoch)?;
    Ok(())
}

fn shape_scope(value: &Value) -> Result<(), FragmentError> {
    let [run, scope, announced, effective] = members(value)?;
    fixed::<32>(run)?;
    octets(scope)?;
    unsigned(announced)?;
    unsigned(effective)?;
    Ok(())
}

fn shape_prior(value: &Value) -> Result<(), FragmentError> {
    let [scope, first, end] = members(value)?;
    octets(scope)?;
    if unsigned(first)? != 0 {
        return Err(FragmentError::Shape);
    }
    unsigned(end)?;
    Ok(())
}

fn shape_paper(value: &Value) -> Result<(), FragmentError> {
    let [
        edition,
        reference,
        kind,
        scope,
        party,
        rules,
        convention,
        projection,
        selection,
    ] = members(value)?;
    unsigned(edition)?;
    shape_ref(reference)?;
    let kind = unsigned(kind)?;
    shape_scope(scope)?;
    for reference in [party, rules, convention, projection] {
        shape_ref(reference)?;
    }
    let [published, unit] = members(selection)?;
    shape_ref(published)?;
    match (kind, unit) {
        (0, Value::Null) | (1, Value::Array(_)) => return Err(FragmentError::Shape),
        (_, Value::Null) => {}
        (_, other) => shape_ref(other)?,
    }
    Ok(())
}

fn shape_local_declaration(value: &Value) -> Result<(), FragmentError> {
    let [edition, reference, scope, party, rules, convention, projection, run] = members(value)?;
    unsigned(edition)?;
    shape_ref(reference)?;
    shape_scope(scope)?;
    let [party_ref, genesis] = members(party)?;
    shape_ref(party_ref)?;
    fixed::<32>(genesis)?;
    for reference in [rules, convention, projection] {
        shape_ref(reference)?;
    }
    octets(run)?;
    Ok(())
}

fn shape_change(value: &Value) -> Result<(), FragmentError> {
    let values = items(value)?;
    let marker = unsigned(values.first().ok_or(FragmentError::Shape)?)?;
    match (marker, values) {
        (0, [_, old, new]) => {
            shape_ref(old)?;
            shape_ref(new)?;
        }
        (1, [_, old]) => shape_ref(old)?,
        _ => return Err(FragmentError::Shape),
    }
    Ok(())
}

fn shape_paper_boundary(value: &Value) -> Result<(), FragmentError> {
    let [edition, context, active, changes] = members(value)?;
    unsigned(edition)?;
    shape_context(context)?;
    for declaration in items(active)? {
        shape_paper(declaration)?;
    }
    for change in items(changes)? {
        shape_change(change)?;
    }
    Ok(())
}

fn shape_pin(value: &Value) -> Result<(), FragmentError> {
    let [height, hash, buffer] = members(value)?;
    unsigned(height)?;
    fixed::<32>(hash)?;
    unsigned(buffer)?;
    Ok(())
}

fn shape_account(value: &Value) -> Result<(), FragmentError> {
    let [edition, context, pin, run, chain, prior] = members(value)?;
    unsigned(edition)?;
    shape_context(context)?;
    shape_pin(pin)?;
    let [configuration, parameters] = members(run)?;
    octets(configuration)?;
    octets(parameters)?;
    let [first, blocks] = members(chain)?;
    unsigned(first)?;
    for block in items(blocks)? {
        octets(block)?;
    }
    shape_prior(prior)?;
    Ok(())
}

fn shape_id(value: &Value) -> Result<(), FragmentError> {
    let [tag, author, sequence, family] = members(value)?;
    string(tag)?;
    string(author)?;
    unsigned(sequence)?;
    string(family)?;
    Ok(())
}

fn shape_locator(value: &Value) -> Result<(), FragmentError> {
    let [height, transaction, input, prevout] = members(value)?;
    unsigned(height)?;
    unsigned(transaction)?;
    unsigned(input)?;
    fixed::<36>(prevout)?;
    Ok(())
}

fn shape_part(value: &Value) -> Result<(), FragmentError> {
    let [layout, actor, issuance, start, end, prior] = members(value)?;
    if unsigned(layout)? != 1 {
        return Err(FragmentError::Shape);
    }
    string(actor)?;
    shape_locator(issuance)?;
    unsigned(start)?;
    unsigned(end)?;
    shape_prior(prior)?;
    Ok(())
}

fn shape_association(value: &Value) -> Result<(), FragmentError> {
    let [layout, context, position, act, declaration, account, part] = members(value)?;
    if unsigned(layout)? != 1 {
        return Err(FragmentError::Shape);
    }
    shape_context(context)?;
    unsigned(position)?;
    shape_id(act)?;
    shape_ref(declaration)?;
    let [account_context, index] = members(account)?;
    shape_context(account_context)?;
    unsigned(index)?;
    unsigned(part)?;
    Ok(())
}

fn shape_local_boundary(value: &Value) -> Result<(), FragmentError> {
    let [discriminator, edition, context, declaration, account, parts, associations] = members(value)?;
    string(discriminator)?;
    unsigned(edition)?;
    shape_context(context)?;
    shape_local_declaration(declaration)?;
    shape_account(account)?;
    for part in items(parts)? {
        shape_part(part)?;
    }
    for association in items(associations)? {
        shape_association(association)?;
    }
    Ok(())
}

fn selected(selected_edition: u64, input: Option<&[u8]>, limits: &ReadAllowances) -> Result<Value, FragmentError> {
    if selected_edition != 1 {
        return Err(FragmentError::UnsupportedEdition);
    }
    let input = input.ok_or(FragmentError::MissingComponent)?;
    if input.len() > limits.encoded_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    Value::from_canonical_bytes(input).map_err(|_| FragmentError::Canonical)
}

fn encoded(value: &Value, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    let bytes = value.to_canonical_bytes();
    if bytes.len() > limits.encoded_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    Ok(bytes)
}

fn ref_value(value: &ComponentRef) -> Value {
    array([text(&value.namespace), text(&value.name), Value::Unsigned(value.edition)])
}

fn parse_ref(value: &Value) -> Result<ComponentRef, FragmentError> {
    let [namespace, name, edition] = members(value)?;
    let reference = ComponentRef {
        namespace: string(namespace)?.to_owned(),
        name: string(name)?.to_owned(),
        edition: unsigned(edition)?,
    };
    reference.validate().map_err(|_| FragmentError::Field)?;
    Ok(reference)
}

fn context_value(value: &BoundaryContext) -> Value {
    array([bytes(&value.run), bytes(&value.history_scope), Value::Unsigned(value.epoch)])
}

fn parse_context(value: &Value, limits: &ReadAllowances) -> Result<BoundaryContext, FragmentError> {
    shape_context(value)?;
    let [run, history_scope, epoch] = members(value)?;
    let history_scope = octets(history_scope)?;
    if history_scope.is_empty() {
        return Err(FragmentError::Field);
    }
    if history_scope.len() > limits.history_scope_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    Ok(BoundaryContext {
        run: fixed(run)?,
        history_scope: history_scope.to_vec(),
        epoch: unsigned(epoch)?,
    })
}

fn scope_value(value: &CaseScope) -> Value {
    array([
        bytes(&value.run),
        bytes(&value.history_scope),
        Value::Unsigned(value.announced_at),
        Value::Unsigned(value.effective_at),
    ])
}

fn parse_scope(value: &Value, limits: &ReadAllowances) -> Result<CaseScope, FragmentError> {
    shape_scope(value)?;
    let [run, history_scope, announced_at, effective_at] = members(value)?;
    let history_scope = octets(history_scope)?;
    if history_scope.is_empty() {
        return Err(FragmentError::Field);
    }
    if history_scope.len() > limits.history_scope_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    Ok(CaseScope {
        run: fixed(run)?,
        history_scope: history_scope.to_vec(),
        announced_at: unsigned(announced_at)?,
        effective_at: unsigned(effective_at)?,
    })
}

fn prior_value(value: &PriorRange) -> Value {
    array([
        bytes(&value.history_scope),
        Value::Unsigned(value.first_epoch),
        Value::Unsigned(value.exclusive_end),
    ])
}

fn parse_prior(value: &Value, limits: &ReadAllowances) -> Result<PriorRange, FragmentError> {
    shape_prior(value)?;
    let [history_scope, first_epoch, exclusive_end] = members(value)?;
    let history_scope = octets(history_scope)?;
    if history_scope.is_empty() {
        return Err(FragmentError::Field);
    }
    if history_scope.len() > limits.history_scope_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    let first_epoch = unsigned(first_epoch)?;
    if first_epoch != 0 {
        return Err(FragmentError::Shape);
    }
    Ok(PriorRange {
        history_scope: history_scope.to_vec(),
        first_epoch,
        exclusive_end: unsigned(exclusive_end)?,
    })
}

fn paper_value(value: &PaperCaseDeclaration) -> Value {
    let kind = match value.kind {
        PaperCaseKind::Provenance => 0,
        PaperCaseKind::AuthorAuthority => 1,
    };
    array([
        Value::Unsigned(1),
        ref_value(&value.reference),
        Value::Unsigned(kind),
        scope_value(&value.scope),
        ref_value(&value.second_party),
        ref_value(&value.rules),
        ref_value(&value.convention),
        ref_value(&value.projection),
        array([
            ref_value(&value.published_data_rule),
            value.unit.as_ref().map_or(Value::Null, ref_value),
        ]),
    ])
}

fn parse_paper(value: &Value, limits: &ReadAllowances) -> Result<PaperCaseDeclaration, FragmentError> {
    shape_paper(value)?;
    let [
        edition,
        reference,
        kind,
        scope,
        second_party,
        rules,
        convention,
        projection,
        data_selection,
    ] = members(value)?;
    let edition = unsigned(edition)?;
    let kind = unsigned(kind)?;
    if edition != 1 {
        return Err(FragmentError::Edition);
    }
    let kind = match kind {
        0 => PaperCaseKind::Provenance,
        1 => PaperCaseKind::AuthorAuthority,
        _ => return Err(FragmentError::Kind),
    };
    let [published_data_rule, unit] = members(data_selection)?;
    let reference = parse_ref(reference)?;
    let scope = parse_scope(scope, limits)?;
    let second_party = parse_ref(second_party)?;
    let rules = parse_ref(rules)?;
    let convention = parse_ref(convention)?;
    let projection = parse_ref(projection)?;
    let published_data_rule = parse_ref(published_data_rule)?;
    let unit = match unit {
        Value::Null => None,
        other => Some(parse_ref(other)?),
    };
    let paper = PaperCaseDeclaration {
        reference,
        kind,
        scope,
        second_party,
        rules,
        convention,
        projection,
        published_data_rule,
        unit,
    };
    paper.validate().map_err(|_| FragmentError::Field)?;
    Ok(paper)
}

/// Encode a selected paper declaration without claiming its in-force truth.
/// # Errors
/// Refuses a malformed typed member or unavailable byte allowance.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::encode_paper_declaration"
    ),
    ret
)]
pub fn encode_paper_declaration(value: &PaperCaseDeclaration, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    value.validate().map_err(|_| FragmentError::Field)?;
    encoded(&paper_value(value), limits)
}

/// Decode a caller-selected paper declaration as representation only.
/// # Errors
/// Refuses in the admitted standalone framing order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::decode_paper_declaration"
    ),
    ret
)]
pub fn decode_paper_declaration(
    input: Option<&[u8]>,
    selected_edition: u64,
    limits: &ReadAllowances,
) -> Result<PaperCaseDeclaration, FragmentError> {
    parse_paper(&selected(selected_edition, input, limits)?, limits)
}

fn local_declaration_value(value: &LocalAuthorityDeclaration) -> Value {
    array([
        Value::Unsigned(1),
        ref_value(&value.reference),
        scope_value(&value.scope),
        array([ref_value(&value.second_party), bytes(&value.genesis_hash)]),
        ref_value(&value.rules),
        ref_value(&value.authorization_convention),
        ref_value(&value.projection),
        bytes(&value.run_configuration),
    ])
}

fn parse_local_declaration(value: &Value, limits: &ReadAllowances) -> Result<LocalAuthorityDeclaration, FragmentError> {
    shape_local_declaration(value)?;
    let [
        edition,
        reference,
        scope,
        second_party,
        rules,
        convention,
        projection,
        run_configuration,
    ] = members(value)?;
    let edition = unsigned(edition)?;
    if edition != 1 {
        return Err(FragmentError::Edition);
    }
    let [party, genesis_hash] = members(second_party)?;
    let local = LocalAuthorityDeclaration {
        reference: parse_ref(reference)?,
        scope: parse_scope(scope, limits)?,
        second_party: parse_ref(party)?,
        genesis_hash: fixed(genesis_hash)?,
        rules: parse_ref(rules)?,
        authorization_convention: parse_ref(convention)?,
        projection: parse_ref(projection)?,
        run_configuration: octets(run_configuration)?.to_vec(),
    };
    local.validate().map_err(|_| FragmentError::Field)?;
    Ok(local)
}

/// Encode a selected local declaration without an authority conclusion.
/// # Errors
/// Refuses malformed typed members or unavailable byte allowance.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::encode_local_declaration"
    ),
    ret
)]
pub fn encode_local_declaration(value: &LocalAuthorityDeclaration, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    value.validate().map_err(|_| FragmentError::Field)?;
    encoded(&local_declaration_value(value), limits)
}

/// Decode a caller-selected local declaration as representation only.
/// # Errors
/// Refuses in the admitted standalone framing order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::decode_local_declaration"
    ),
    ret
)]
pub fn decode_local_declaration(
    input: Option<&[u8]>,
    selected_edition: u64,
    limits: &ReadAllowances,
) -> Result<LocalAuthorityDeclaration, FragmentError> {
    parse_local_declaration(&selected(selected_edition, input, limits)?, limits)
}

fn change_value(value: &PaperChange) -> Value {
    match value {
        PaperChange::Successor { old, new } => array([Value::Unsigned(0), ref_value(old), ref_value(new)]),
        PaperChange::Withdrawal { old } => array([Value::Unsigned(1), ref_value(old)]),
    }
}

fn parse_change(value: &Value) -> Result<PaperChange, FragmentError> {
    let items = items(value)?;
    let Some(marker) = items.first() else {
        return Err(FragmentError::Shape);
    };
    match (unsigned(marker)?, items) {
        (0, [_, old, new]) => Ok(PaperChange::Successor {
            old: parse_ref(old)?,
            new: parse_ref(new)?,
        }),
        (1, [_, old]) => Ok(PaperChange::Withdrawal { old: parse_ref(old)? }),
        _ => Err(FragmentError::Shape),
    }
}

fn paper_boundary_value(value: &PaperCaseBoundary) -> Value {
    array([
        Value::Unsigned(1),
        context_value(&value.context),
        array(value.active.iter().map(paper_value)),
        array(value.changes.iter().map(change_value)),
    ])
}

fn parse_paper_boundary(value: &Value, limits: &ReadAllowances) -> Result<PaperCaseBoundary, FragmentError> {
    shape_paper_boundary(value)?;
    let [edition, context, active, changes] = members(value)?;
    let edition = unsigned(edition)?;
    if edition != 1 {
        return Err(FragmentError::Edition);
    }
    let active = items(active)?;
    let changes = items(changes)?;
    if active.len() > limits.declarations || changes.len() > limits.transitions {
        return Err(FragmentError::UnavailableBudget);
    }
    let boundary = PaperCaseBoundary {
        context: parse_context(context, limits)?,
        active: active
            .iter()
            .map(|item| parse_paper(item, limits).map_err(nested_component))
            .collect::<Result<_, _>>()?,
        changes: changes.iter().map(parse_change).collect::<Result<_, _>>()?,
    };
    for pair in boundary.active.windows(2) {
        if pair[0].reference > pair[1].reference {
            return Err(FragmentError::Order);
        }
    }
    for pair in boundary.changes.windows(2) {
        if pair[0].old() > pair[1].old() {
            return Err(FragmentError::Order);
        }
    }
    for pair in boundary.active.windows(2) {
        if pair[0].reference == pair[1].reference {
            return Err(FragmentError::Duplicate);
        }
    }
    for pair in boundary.changes.windows(2) {
        if pair[0].old() == pair[1].old() {
            return Err(FragmentError::Duplicate);
        }
    }
    Ok(boundary)
}

/// Encode a complete paper boundary, including its explicit empty set and changes.
/// # Errors
/// Refuses a malformed typed member or unavailable reader allowance.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::encode_paper_boundary"
    ),
    ret
)]
pub fn encode_paper_boundary(value: &PaperCaseBoundary, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    let encoded = encoded(&paper_boundary_value(value), limits)?;
    parse_paper_boundary(
        &Value::from_canonical_bytes(&encoded).map_err(|_| FragmentError::Canonical)?,
        limits,
    )?;
    Ok(encoded)
}

/// Decode a caller-selected paper boundary as representation only.
/// # Errors
/// Refuses in the admitted standalone framing order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::decode_paper_boundary"
    ),
    ret
)]
pub fn decode_paper_boundary(
    input: Option<&[u8]>,
    selected_edition: u64,
    limits: &ReadAllowances,
) -> Result<PaperCaseBoundary, FragmentError> {
    parse_paper_boundary(&selected(selected_edition, input, limits)?, limits)
}

fn pin_value(value: &AccountPin) -> Value {
    array([
        Value::Unsigned(value.height),
        bytes(&value.block_hash),
        Value::Unsigned(value.buffer),
    ])
}

fn parse_pin(value: &Value) -> Result<AccountPin, FragmentError> {
    let [height, block_hash, buffer] = members(value)?;
    Ok(AccountPin {
        height: unsigned(height)?,
        block_hash: fixed(block_hash)?,
        buffer: unsigned(buffer)?,
    })
}

fn account_value(value: &AuthorityAccount) -> Value {
    array([
        Value::Unsigned(1),
        context_value(&value.context),
        pin_value(&value.pin),
        array([bytes(&value.run_configuration), bytes(&value.chain_parameters)]),
        array([
            Value::Unsigned(value.first_height),
            array(value.blocks.iter().map(|block| bytes(block))),
        ]),
        prior_value(&value.prior_range),
    ])
}

fn parse_account(value: &Value, limits: &ReadAllowances) -> Result<AuthorityAccount, FragmentError> {
    shape_account(value)?;
    let [edition, context, pin, run_evidence, chain_evidence, prior] = members(value)?;
    let edition = unsigned(edition)?;
    if edition != 1 {
        return Err(FragmentError::Edition);
    }
    let [run_configuration, chain_parameters] = members(run_evidence)?;
    let [first_height, blocks] = members(chain_evidence)?;
    let blocks = items(blocks)?;
    if blocks.len() > limits.blocks {
        return Err(FragmentError::UnavailableBudget);
    }
    let mut total = 0usize;
    let mut block_values = Vec::with_capacity(blocks.len());
    for block in blocks {
        let block = octets(block)?;
        total = total.checked_add(block.len()).ok_or(FragmentError::Shape)?;
        if total > limits.block_bytes {
            return Err(FragmentError::UnavailableBudget);
        }
        block_values.push(block.to_vec());
    }
    Ok(AuthorityAccount {
        context: parse_context(context, limits)?,
        pin: parse_pin(pin)?,
        run_configuration: octets(run_configuration)?.to_vec(),
        chain_parameters: octets(chain_parameters)?.to_vec(),
        first_height: unsigned(first_height)?,
        blocks: block_values,
        prior_range: parse_prior(prior, limits)?,
    })
}

/// Encode a full selected account without replacing the chain evaluator.
/// # Errors
/// Refuses malformed typed members or unavailable reader allowances.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::encode_account"
    ),
    ret
)]
pub fn encode_account(value: &AuthorityAccount, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    let encoded = encoded(&account_value(value), limits)?;
    if encoded.len() > limits.account_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    parse_account(
        &Value::from_canonical_bytes(&encoded).map_err(|_| FragmentError::Canonical)?,
        limits,
    )?;
    Ok(encoded)
}

/// Decode a caller-selected full account as representation only.
/// # Errors
/// Refuses in the admitted standalone framing order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::decode_account"
    ),
    ret
)]
pub fn decode_account(
    input: Option<&[u8]>,
    selected_edition: u64,
    limits: &ReadAllowances,
) -> Result<AuthorityAccount, FragmentError> {
    if selected_edition != 1 {
        return Err(FragmentError::UnsupportedEdition);
    }
    let input = input.ok_or(FragmentError::MissingComponent)?;
    if input.len() > limits.encoded_bytes || input.len() > limits.account_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    let value = Value::from_canonical_bytes(input).map_err(|_| FragmentError::Canonical)?;
    parse_account(&value, limits)
}

fn id_value(value: &ActId) -> Value {
    array([
        text("act"),
        text(&value.author),
        Value::Unsigned(value.sequence),
        text(&value.family),
    ])
}

fn parse_id(value: &Value) -> Result<ActId, FragmentError> {
    shape_id(value)?;
    let [tag, author, sequence, family] = members(value)?;
    if string(tag)? != "act" {
        return Err(FragmentError::Field);
    }
    let id = ActId {
        author: string(author)?.to_owned(),
        sequence: unsigned(sequence)?,
        family: string(family)?.to_owned(),
    };
    if !valid_act_id(&id) {
        return Err(FragmentError::Field);
    }
    Ok(id)
}

fn locator_value(value: &IssuanceLocator) -> Value {
    array([
        Value::Unsigned(value.height),
        Value::Unsigned(value.transaction_index),
        Value::Unsigned(value.input_index),
        bytes(&value.issuance_prevout),
    ])
}

fn parse_locator(value: &Value) -> Result<IssuanceLocator, FragmentError> {
    let [height, transaction_index, input_index, issuance_prevout] = members(value)?;
    Ok(IssuanceLocator {
        height: unsigned(height)?,
        transaction_index: unsigned(transaction_index)?,
        input_index: unsigned(input_index)?,
        issuance_prevout: fixed(issuance_prevout)?,
    })
}

fn part_value(value: &ActorPart) -> Value {
    array([
        Value::Unsigned(1),
        text(&value.actor),
        locator_value(&value.issuance),
        Value::Unsigned(value.scan_from),
        Value::Unsigned(value.scan_through),
        prior_value(&value.prior_range),
    ])
}

fn parse_part(value: &Value, limits: &ReadAllowances) -> Result<ActorPart, FragmentError> {
    shape_part(value)?;
    let [_layout, actor, issuance, scan_from, scan_through, prior_range] = members(value)?;
    let actor = string(actor)?.to_owned();
    if !valid_act_id(&ActId {
        author: actor.clone(),
        sequence: 0,
        family: "Registration".to_owned(),
    }) {
        return Err(FragmentError::Field);
    }
    Ok(ActorPart {
        actor,
        issuance: parse_locator(issuance)?,
        scan_from: unsigned(scan_from)?,
        scan_through: unsigned(scan_through)?,
        prior_range: parse_prior(prior_range, limits)?,
    })
}

fn association_value(value: &ActAssociation) -> Value {
    array([
        Value::Unsigned(1),
        context_value(&value.context),
        Value::Unsigned(value.act_position),
        id_value(&value.act),
        ref_value(&value.local_declaration),
        array([context_value(&value.account_context), Value::Unsigned(value.account_index)]),
        Value::Unsigned(value.part_index),
    ])
}

fn parse_association(value: &Value, limits: &ReadAllowances) -> Result<ActAssociation, FragmentError> {
    shape_association(value)?;
    let [
        _layout,
        context,
        act_position,
        act,
        local_declaration,
        account_reference,
        part_index,
    ] = members(value)?;
    let [account_context, account_index] = members(account_reference)?;
    Ok(ActAssociation {
        context: parse_context(context, limits)?,
        act_position: unsigned(act_position)?,
        act: parse_id(act)?,
        local_declaration: parse_ref(local_declaration)?,
        account_context: parse_context(account_context, limits)?,
        account_index: unsigned(account_index)?,
        part_index: unsigned(part_index)?,
    })
}

fn local_boundary_value(value: &LocalAuthorityBoundary) -> Value {
    array([
        text("org.peer-network.test.publication.author-authority"),
        Value::Unsigned(1),
        context_value(&value.context),
        local_declaration_value(&value.declaration),
        account_value(&value.account),
        array(value.parts.iter().map(part_value)),
        array(value.associations.iter().map(association_value)),
    ])
}

fn parse_local_boundary(value: &Value, limits: &ReadAllowances) -> Result<LocalAuthorityBoundary, FragmentError> {
    shape_local_boundary(value)?;
    let [discriminator, edition, context, declaration, account, parts, associations] = members(value)?;
    if string(discriminator)? != "org.peer-network.test.publication.author-authority" {
        return Err(FragmentError::Shape);
    }
    let edition = unsigned(edition)?;
    if edition != 1 {
        return Err(FragmentError::Edition);
    }
    let parts = items(parts)?;
    let associations = items(associations)?;
    if parts.len() > limits.parts || associations.len() > limits.associations {
        return Err(FragmentError::UnavailableBudget);
    }
    if account.to_canonical_bytes().len() > limits.account_bytes {
        return Err(FragmentError::UnavailableBudget);
    }
    let boundary = LocalAuthorityBoundary {
        context: parse_context(context, limits)?,
        declaration: parse_local_declaration(declaration, limits).map_err(nested_component)?,
        account: parse_account(account, limits).map_err(nested_component)?,
        parts: parts
            .iter()
            .map(|item| parse_part(item, limits).map_err(nested_component))
            .collect::<Result<_, _>>()?,
        associations: associations
            .iter()
            .map(|item| parse_association(item, limits).map_err(nested_component))
            .collect::<Result<_, _>>()?,
    };
    for pair in boundary.parts.windows(2) {
        if pair[0].actor > pair[1].actor {
            return Err(FragmentError::Order);
        }
    }
    for pair in boundary.associations.windows(2) {
        if pair[0].act_position > pair[1].act_position {
            return Err(FragmentError::Order);
        }
    }
    for pair in boundary.parts.windows(2) {
        if pair[0].actor == pair[1].actor {
            return Err(FragmentError::Duplicate);
        }
    }
    for pair in boundary.associations.windows(2) {
        if pair[0].act_position == pair[1].act_position {
            return Err(FragmentError::Duplicate);
        }
    }
    Ok(boundary)
}

/// Encode the required local boundary without a holder fact or dependency list.
/// # Errors
/// Refuses a malformed typed member or unavailable reader allowance.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::encode_local_boundary"
    ),
    ret
)]
pub fn encode_local_boundary(value: &LocalAuthorityBoundary, limits: &ReadAllowances) -> Result<Vec<u8>, FragmentError> {
    let encoded = encoded(&local_boundary_value(value), limits)?;
    parse_local_boundary(
        &Value::from_canonical_bytes(&encoded).map_err(|_| FragmentError::Canonical)?,
        limits,
    )?;
    Ok(encoded)
}

/// Decode a caller-selected local boundary as representation only.
/// # Errors
/// Refuses in the admitted standalone framing order.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "boundary_components::decode_local_boundary"
    ),
    ret
)]
pub fn decode_local_boundary(
    input: Option<&[u8]>,
    selected_edition: u64,
    limits: &ReadAllowances,
) -> Result<LocalAuthorityBoundary, FragmentError> {
    parse_local_boundary(&selected(selected_edition, input, limits)?, limits)
}
