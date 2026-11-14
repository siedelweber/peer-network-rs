//! Caller-budgeted position projection of a borrowed admitted package.
//! Nested declaration, policy, address and amount projections remain pinned to
//! publication 1.0.0 for the life of this recipe, independently of later writers.
//! (´[ROOT-amend:identity:result-position-recipe]´)

use pn_epoch::publication::{AdmittedPackage, Frame};
use pn_interchange::{Array, Bytes, EncodingError, EncodingUsage, Map, Text, TransferError, Value};
use pn_records::{Declaration, DeclarationContent, burn};
use std::collections::BTreeSet;

/// The admitted result-position recipe; no alternate framing is inferred.
/// (´[ROOT-amend:identity:result-position-recipe]´)
pub const RECIPE: &str = "pn-host/result-position/v1";
const TAG: &str = "PN-result-position-v1";

/// The representation cause is retained without a partial position.
/// (´[ROOT-amend:identity:result-position-recipe]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Representation {
    Encoding(EncodingError),
    Transfer(TransferError),
    Range,
}

/// Refusal leaves admission unchanged and produces no usable position.
/// (´[ROOT-amend:identity:result-position-recipe]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPosition,
    Representation(Representation),
    UnsupportedPositionRecipe,
}
impl From<EncodingError> for Error {
    /// Wrap the exact public encoding refusal without repairing it.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Pure refusal wrapping inherits the budgeted position boundary; it grants no admission and allocates nothing.
    fn from(error: EncodingError) -> Self {
        Self::Representation(Representation::Encoding(error))
    }
}
impl From<TransferError> for Error {
    /// Wrap the exact public ownership-transfer refusal without repairing it.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Pure refusal wrapping inherits the budgeted position boundary; it grants no admission and allocates nothing.
    fn from(error: TransferError) -> Self {
        Self::Representation(Representation::Transfer(error))
    }
}

/// A position retains an immutable borrow of its admitted causes, never a decoded capability.
/// Construction of the retaining `AdmittedEpoch` remains outside this projection meter:
/// that existing operation clones and re-encodes the complete disclosure.
/// Observation and the caller's callback are outside the meter; no allocator census is claimed.
/// (´[ROOT-amend:identity:result-position-recipe]´)
/// ```compile_fail
/// fn from_decoded(value: pn_epoch::publication::disclosures::Disclosure) {
///     pn_host::position::Position::from_package(&value, None,
///         pn_host::position::RECIPE, usize::MAX,
///         &mut pn_interchange::EncodingUsage::default(), |_| Ok(()));
/// }
/// ```
#[derive(Debug)]
pub struct Position<'a> {
    package: &'a AdmittedPackage,
    residue: [u8; 32],
    parent: Option<[u8; 32]>,
    depth: u64,
}

impl<'a> Position<'a> {
    /// Compute the position from admitted causes and an explicitly named admitted parent.
    /// Usage resets at entry and includes every admitted construction and encoding request,
    /// on success and refusal. The caller sizes the ceiling to the complete supplied sets.
    /// No tag value or nonempty map occurs in this projection; nested publication forms
    /// are constructed directly under the meter, never by the allocating publication writer.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// # Errors
    /// Invalid shape, acceptance or parent binding refuses `InvalidPosition`; unsupported
    /// recipes refuse `UnsupportedPositionRecipe`. `Representation` retains all four encoder
    /// refusals, transfer refusal (including allocator spare capacity), or a storage range refusal.
    /// The current admission carrier cannot express either policy-edition transition.
    /// # Panics
    /// A panicking reservation callback propagates with usage at earlier admitted requests;
    /// complete values and partial children are explicitly disposed during unwinding.
    pub fn from_package(
        package: &'a AdmittedPackage,
        parent: Option<&Self>,
        recipe: &str,
        ceiling: usize,
        usage: &mut EncodingUsage,
        mut reservation: impl FnMut(usize) -> Result<(), ()>,
    ) -> Result<Self, Error> {
        let operation = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "admitted_result::position::Position < 'a >::from_package",
            &(
                package,
                parent,
                recipe,
                ceiling,
                "reservation callback is an executable capability",
            ),
        );
        *usage = EncodingUsage::default();
        let result = (|| {
            if recipe != RECIPE {
                return Err(Error::UnsupportedPositionRecipe);
            }
            let input = Input::admitted(package)?;
            let previous = parent.map(|p| Input::admitted(p.package)).transpose()?;
            input.validate(previous.as_ref())?;
            let depth = parent
                .map_or(Some(1), |p| p.depth.checked_add(1))
                .ok_or(Error::InvalidPosition)?;
            signed(depth)?;
            let parent_id = parent.map(|p| p.residue);
            let mut builder = Builder {
                ceiling,
                usage,
                reservation: &mut reservation,
            };
            let bytes = builder.preimage(&input, previous.as_ref(), parent_id.as_ref())?;
            let residue = crate::storage::digest(RECIPE, &bytes);
            Ok(Self {
                package,
                residue,
                parent: parent_id,
                depth,
            })
        })();
        tracing::event!(tracing::Level::TRACE, projection_usage = ?usage);
        operation.finish(&result);
        result
    }

    /// Borrow the fixed residue whose parent commitment names this whole ancestry.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Immutable projection access inherits the recorded position constructor.
    #[must_use]
    pub const fn residue(&self) -> &[u8; 32] {
        &self.residue
    }

    /// Borrow the explicit parent, absent only for a first result above the initial marker.
    /// (´[ROOT-amend:storage:admitted-event]´)
    /// Justified: Immutable projection access inherits the recorded position constructor.
    #[must_use]
    pub const fn parent(&self) -> Option<&[u8; 32]> {
        self.parent.as_ref()
    }

    /// Tree depth is independent of a future policy edition's local marker index.
    /// (´[ROOT-amend:storage:admitted-event]´)
    /// Justified: Immutable projection access inherits the recorded position constructor.
    #[must_use]
    pub const fn depth(&self) -> u64 {
        self.depth
    }
}

/// Complete package retention with result-qualified observation versions.
/// This carrier is not accepted by either existing chain-store commit operation.
/// (´[ROOT-amend:storage:admitted-correspondence]´)
#[derive(Debug)]
pub struct Retained {
    inner: super::AdmittedEpoch,
    identity: [u8; 32],
    parent: Option<[u8; 32]>,
    depth: u64,
    context: Context,
}

#[derive(Debug)]
struct Context {
    genesis: Declaration,
    policy: burn::PolicyInput,
    initial: burn::RecognizedMarker,
    records: Vec<burn::BurnRecord>,
}
impl Retained {
    /// Retain complete canonical bytes and selections after the position is computed.
    /// This construction clones and re-encodes outside the position projection's meter.
    /// (´[ROOT-amend:storage:admitted-correspondence]´)
    /// # Errors
    /// Preserves the existing carrier's codec, correspondence and representation refusals.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::position::Retained::from_position"
        ),
        ret
    )]
    pub fn from_position(
        position: &Position<'_>,
        numeric: &mut pn_records::numerics::NumericContext,
        limits: pn_epoch::publication::disclosures::Limits,
    ) -> Result<Self, super::CarrierError> {
        use std::fmt::Write;
        let mut inner = super::AdmittedEpoch::project(position.package, numeric, limits)?;
        let mut identity = String::with_capacity(64);
        for byte in position.residue {
            write!(identity, "{byte:02x}").map_err(|_| super::CarrierError::Representation)?;
        }
        let document =
            pn_interchange::Document::from_canonical_bytes(&inner.bytes).map_err(|_| super::CarrierError::Correspondence)?;
        inner.declarations =
            super::projection::declarations(position.package, &document, &inner.event, Some((&identity, position.depth)))?;
        let input = Input::admitted(position.package).map_err(|_| super::CarrierError::Correspondence)?;
        let context = Context {
            genesis: input.genesis.clone(),
            policy: input.frame.marker_policy.clone(),
            initial: input.initial.clone(),
            records: input
                .frame
                .marker_history
                .records
                .iter()
                .filter(|r| input.initial.identity().lineage.contains(&r.identity))
                .cloned()
                .collect(),
        };
        Ok(Self {
            inner,
            identity: position.residue,
            parent: position.parent,
            depth: position.depth,
            context,
        })
    }

    /// Borrow the complete retained canonical package, without admission from bytes.
    /// (´[ROOT-amend:storage:admitted-correspondence]´)
    /// Justified: Immutable field access inherits the recorded retaining constructor.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Borrow exact result-qualified observations and dated declarations.
    /// (´[ROOT-amend:storage:admitted-correspondence]´)
    /// Justified: Immutable field access inherits the recorded retaining constructor.
    #[must_use]
    pub fn declarations(&self) -> &[super::DeclarationUse] {
        &self.inner.declarations
    }

    /// Borrow the original public scope, position, parent and depth without selecting a tip.
    /// (´[ROOT-amend:storage:admitted-event]´)
    /// Justified: Immutable field access inherits the recorded retaining constructor.
    #[must_use]
    pub fn event(&self) -> (&super::EpochScope, &[u8; 32], Option<&[u8; 32]>, u64) {
        (&self.inner.event.scope, &self.identity, self.parent.as_ref(), self.depth)
    }

    /// Borrow the original complete debit vintages for ancestor-relative comparison.
    /// (´[ROOT-amend:storage:admitted-debits]´)
    /// Justified: Immutable projection access inherits the caller-owned retaining constructor.
    pub(crate) fn debits(&self) -> &[super::DebitVintage] {
        &self.inner.debits
    }

    /// Compare the complete starting context without interpreting evidence as identity.
    /// (´[ROOT-amend:storage:admitted-event]´)
    /// Justified: Allocation-free comparison of the caller-owned context inherits transaction observation.
    pub(crate) fn same_context(&self, other: &Self) -> bool {
        let (a, b) = (&self.context, &other.context);
        a.genesis == b.genesis
            && a.policy == b.policy
            && same_marker(&a.initial, &b.initial)
            && a.records.len() == b.records.len()
            && a.records.iter().all(|r| b.records.iter().any(|s| same_record(r, s)))
    }

    /// Preserve complete inherited bindings while allowing disclosure-only marker evidence.
    /// (´[ROOT-amend:storage:admitted-event]´)
    /// Justified: Borrowed prefix comparison inherits transaction observation and constructs no carrier.
    pub(crate) fn extends(&self, parent: &Self) -> bool {
        if self.inner.bindings.len() < parent.inner.bindings.len() {
            return false;
        }
        self.inner.bindings.iter().zip(&parent.inner.bindings).all(|(a, b)| {
            same_marker_identity(&a.marker, &b.marker)
                && same_marker_identity(&a.predecessor, &b.predecessor)
                && a.inputs == b.inputs
                && a.price == b.price
                && a.sequence == b.sequence
        })
    }
}

fn unique_genesis(declarations: &[Declaration]) -> Result<&Declaration, Error> {
    let mut declarations = declarations
        .iter()
        .filter(|d| d.id.namespace == "deployment" && d.id.name == "genesis");
    let genesis = declarations.next().ok_or(Error::InvalidPosition)?;
    if declarations.next().is_some() {
        return Err(Error::InvalidPosition);
    }
    Ok(genesis)
}

struct Input<'a> {
    frame: &'a Frame,
    genesis: &'a Declaration,
    initial: &'a burn::RecognizedMarker,
    terminal: &'a burn::RecognizedMarker,
}
impl<'a> Input<'a> {
    fn admitted(package: &'a AdmittedPackage) -> Result<Self, Error> {
        Self::carrier(package.carrier())
    }

    // Private input boundary: tests can supply malformed carriers without forging admission.
    fn carrier(carrier: &'a pn_epoch::publication::Carrier) -> Result<Self, Error> {
        let frame = carrier.frames.last().ok_or(Error::InvalidPosition)?;
        let markers = frame.closure.markers.markers();
        let initial = markers.first().ok_or(Error::InvalidPosition)?;
        let terminal = markers
            .iter()
            .find(|m| m.identity().index == frame.parameters.boundary)
            .ok_or(Error::InvalidPosition)?;
        let genesis = unique_genesis(&carrier.causes.declarations)?;
        if !matches!(genesis.content, DeclarationContent::Deployment { genesis_at } if genesis_at == frame.marker_policy.genesis_at)
        {
            return Err(Error::InvalidPosition);
        }
        Ok(Self {
            frame,
            genesis,
            initial,
            terminal,
        })
    }

    fn validate(&self, parent: Option<&Self>) -> Result<(), Error> {
        let policy = &self.frame.marker_policy;
        let initial = self.initial.identity();
        check_marker(self.initial, policy, true)?;
        check_marker(self.terminal, policy, false)?;
        if initial.name != policy.initial_marker || initial.history != self.frame.marker_history.identity {
            return Err(Error::InvalidPosition);
        }
        let base = parent.map_or(self.initial, |p| p.terminal);
        let marker = self.terminal.identity();
        if marker.index != base.identity().index.checked_add(1).ok_or(Error::InvalidPosition)?
            || marker.predecessor != Some(base.identity().history_position)
            || marker.history_position <= base.identity().history_position
            || scope(marker) != scope(base.identity())
            || !base.accepted().is_subset(self.terminal.accepted())
            || !base.identity().lineage.is_subset(&marker.lineage)
        {
            return Err(Error::InvalidPosition);
        }
        if let Some(parent) = parent {
            // The current carrier has no public re-anchor/follow continuity.
            if self.genesis != parent.genesis
                || policy != &parent.frame.marker_policy
                || !same_marker(self.initial, parent.initial)
            {
                return Err(Error::InvalidPosition);
            }
            let disclosed_parent = self
                .frame
                .closure
                .markers
                .markers()
                .iter()
                .find(|m| m.identity().index == base.identity().index)
                .ok_or(Error::InvalidPosition)?;
            if !same_marker(disclosed_parent, base) {
                return Err(Error::InvalidPosition);
            }
            for identity in &base.identity().lineage {
                let old = record(&parent.frame.marker_history, identity)?;
                let new = record(&self.frame.marker_history, identity)?;
                if !same_record(old, new) {
                    return Err(Error::InvalidPosition);
                }
            }
        }
        for marker in [initial, self.terminal.identity()] {
            for identity in &marker.lineage {
                record(&self.frame.marker_history, identity)?;
            }
            scope_range(marker)?;
            signed(marker.index)?;
            signed(marker.history_position)?;
            if let Some(position) = marker.predecessor {
                signed(position)?;
            }
        }
        Ok(())
    }
}
fn signed(value: u64) -> Result<(), Error> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| Error::Representation(Representation::Range))
}
fn scope_range(marker: &burn::Marker) -> Result<(), Error> {
    let mut size = 2usize; // K's four-component count and colon.
    for value in scope(marker) {
        let digits = if value.is_empty() {
            1
        } else {
            value.len().ilog10() as usize + 1
        };
        size = size
            .checked_add(digits)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(Error::Representation(Representation::Range))?;
    }
    if size > 1024 {
        Err(Error::Representation(Representation::Range))
    } else {
        Ok(())
    }
}
fn scope(marker: &burn::Marker) -> [&str; 4] {
    [
        &marker.history,
        &marker.policy_identity,
        &marker.policy_edition,
        &marker.sequence,
    ]
}
fn record<'a>(history: &'a burn::HistoryInput, identity: &str) -> Result<&'a burn::BurnRecord, Error> {
    let mut found = history.records.iter().filter(|r| r.identity == identity);
    let record = found.next().ok_or(Error::InvalidPosition)?;
    if found.next().is_some() {
        return Err(Error::InvalidPosition);
    }
    Ok(record)
}
fn same_record(a: &burn::BurnRecord, b: &burn::BurnRecord) -> bool {
    a.identity == b.identity
        && a.destruction == b.destruction
        && a.address == b.address
        && a.amount.exact() == b.amount.exact()
        && a.amount.unit() == b.amount.unit()
}
fn same_marker(a: &burn::RecognizedMarker, b: &burn::RecognizedMarker) -> bool {
    let (x, y) = (a.identity(), b.identity());
    a.accepted() == b.accepted() && same_marker_identity(x, y)
}
fn same_marker_identity(x: &burn::Marker, y: &burn::Marker) -> bool {
    scope(x) == scope(y)
        && x.index == y.index
        && x.history_position == y.history_position
        && x.predecessor == y.predecessor
        && x.lineage == y.lineage
        && match (&x.accepted, &y.accepted) {
            (burn::AcceptedSet::CompleteList(a), burn::AcceptedSet::CompleteList(b)) => a == b,
            (burn::AcceptedSet::WholePrefix, burn::AcceptedSet::WholePrefix) => true,
            (burn::AcceptedSet::Commitment { commitment: a, .. }, burn::AcceptedSet::Commitment { commitment: b, .. }) => a == b,
            _ => false,
        }
}
fn check_marker(marker: &burn::RecognizedMarker, policy: &burn::PolicyInput, initial: bool) -> Result<(), Error> {
    check_acceptance(marker.identity(), marker.accepted(), policy, initial)
}
fn check_acceptance(
    m: &burn::Marker,
    accepted: &BTreeSet<String>,
    policy: &burn::PolicyInput,
    initial: bool,
) -> Result<(), Error> {
    if (&m.policy_identity, &m.policy_edition, &m.sequence) != (&policy.identity, &policy.edition, &policy.sequence)
        || !accepted.is_subset(&m.lineage)
    {
        return Err(Error::InvalidPosition);
    }
    let recovered = match (&m.accepted, policy.encoding) {
        (burn::AcceptedSet::CompleteList(members), burn::Encoding::CompleteList) => members,
        (burn::AcceptedSet::WholePrefix, burn::Encoding::WholePrefixAcceptAll) => &m.lineage,
        (burn::AcceptedSet::Commitment { commitment, openings }, burn::Encoding::PublicCommitment) => {
            let [opening] = openings.as_slice() else {
                return Err(Error::InvalidPosition);
            };
            if commitment.is_empty() || opening.proof.is_empty() {
                return Err(Error::InvalidPosition);
            }
            // This recognized capability comes only from the admitted package's verifier.
            &opening.members
        }
        _ => return Err(Error::InvalidPosition),
    };
    if recovered != accepted
        || (initial
            && (m.index != 0
                || m.predecessor.is_some()
                || !recovered.is_empty()
                || !m.initial_snapshot.as_ref().is_some_and(std::collections::BTreeMap::is_empty)))
        || (!initial && m.initial_snapshot.is_some())
    {
        return Err(Error::InvalidPosition);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

struct Children(Vec<Value>);
impl Drop for Children {
    /// Release partial public projection children through the allocation-free route.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Private cleanup inherits the budgeted position boundary; observation here would add teardown work outside its meter.
    fn drop(&mut self) {
        #[cfg(test)]
        tests::release_site("children", &self.0);
        Value::Array(Array::take_reserved(&mut self.0)).dispose();
    }
}
struct Owned(Option<Value>);
impl Drop for Owned {
    /// Release a complete public projection on success, refusal or unwinding.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Private cleanup inherits the budgeted position boundary; observation here would add teardown work outside its meter.
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            #[cfg(test)]
            tests::release_site("owned", std::slice::from_ref(&value));
            value.dispose();
        }
    }
}
struct CombinedUsage<'a> {
    output: &'a mut EncodingUsage,
    calls: usize,
    bytes: usize,
}
impl Drop for CombinedUsage<'_> {
    /// Restore cumulative admitted usage when encoding returns or unwinds.
    /// (´[ROOT-amend:identity:result-position-recipe]´)
    /// Justified: Private accounting inherits the budgeted position boundary and adds no allocation or independently admitted result.
    fn drop(&mut self) {
        // Both stages share a ceiling and each nonzero reservation consumes bytes.
        self.output.allocation_calls += self.calls;
        self.output.allocation_bytes += self.bytes;
    }
}
struct Builder<'a> {
    ceiling: usize,
    usage: &'a mut EncodingUsage,
    reservation: &'a mut dyn FnMut(usize) -> Result<(), ()>,
}
impl Builder<'_> {
    fn array(&mut self, size: usize, fill: impl FnOnce(&mut Self, &mut Vec<Value>) -> Result<(), Error>) -> Result<Value, Error> {
        let mut items = Children(Vec::new());
        self.usage
            .reserve_value_buffer(&mut items.0, size, self.ceiling, &mut self.reservation)?;
        fill(self, &mut items.0)?;
        Ok(Value::Array(Array::take_reserved(&mut items.0)))
    }
    fn buffer(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        self.usage
            .reserve_value_buffer(&mut output, bytes.len(), self.ceiling, &mut self.reservation)?;
        output.extend_from_slice(bytes);
        Ok(output)
    }
    fn text(&mut self, text: &str) -> Result<Value, Error> {
        Ok(Value::Text(Text::take_reserved(&mut self.buffer(text.as_bytes())?)?))
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<Value, Error> {
        Ok(Value::Bytes(Bytes::take_reserved(&mut self.buffer(bytes)?)?))
    }
    fn decimal(&mut self, mut number: u64) -> Result<Value, Error> {
        // The pinned publication projection uses decimal text, not an integer head.
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + u8::try_from(number % 10).map_err(|_| Error::InvalidPosition)?;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        Ok(Value::Text(Text::take_reserved(&mut self.buffer(&digits[at..])?)?))
    }
    fn set(&mut self, values: &BTreeSet<String>, base: Option<&BTreeSet<String>>) -> Result<Value, Error> {
        let count = values.iter().filter(|v| base.is_none_or(|b| !b.contains(*v))).count();
        self.array(count, |b, out| {
            // String order is UTF-8 byte order; Value comparison allocates and is not used.
            for value in values.iter().filter(|v| base.is_none_or(|b| !b.contains(*v))) {
                out.push(b.text(value)?);
            }
            Ok(())
        })
    }
    fn policy(&mut self, p: &burn::PolicyInput) -> Result<Value, Error> {
        self.array(13, |b, out| {
            for s in [&p.identity, &p.edition, &p.sequence] {
                out.push(b.text(s)?);
            }
            out.push(b.decimal(p.published_at)?);
            out.push(b.decimal(p.genesis_at)?);
            out.push(b.text(&p.initial_marker)?);
            out.push(Value::Bool(p.open_placement));
            out.push(b.text(&p.placement_procedure)?);
            out.push(b.text(&p.cadence)?);
            let encoding = match p.encoding {
                burn::Encoding::CompleteList => 0,
                burn::Encoding::PublicCommitment => 1,
                burn::Encoding::WholePrefixAcceptAll => 2,
            };
            out.push(b.array(1, |_, v| {
                v.push(Value::Unsigned(encoding));
                Ok(())
            })?);
            let candidate = match p.candidate_rule {
                burn::CandidateRule::FirstValidInHistoryOrder => 0,
                burn::CandidateRule::UniquePerIndex => 1,
            };
            out.push(b.array(1, |_, v| {
                v.push(Value::Unsigned(candidate));
                Ok(())
            })?);
            out.push(b.text(&p.verification_profile)?);
            out.push(b.decimal(p.stability_buffer)?);
            Ok(())
        })
    }
    fn declaration(&mut self, d: &Declaration) -> Result<Value, Error> {
        let DeclarationContent::Deployment { genesis_at } = d.content else {
            return Err(Error::InvalidPosition);
        };
        self.array(4, |b, out| {
            out.push(b.array(3, |b, v| {
                v.push(b.text(&d.id.namespace)?);
                v.push(b.text(&d.id.name)?);
                v.push(b.decimal(d.id.edition)?);
                Ok(())
            })?);
            out.push(b.decimal(d.announced_at)?);
            out.push(b.decimal(d.effective_at)?);
            out.push(b.array(2, |b, v| {
                v.push(Value::Unsigned(1));
                v.push(b.decimal(genesis_at)?);
                Ok(())
            })?);
            Ok(())
        })
    }
    fn record(&mut self, r: &burn::BurnRecord) -> Result<Value, Error> {
        self.array(4, |b, out| {
            out.push(b.text(&r.identity)?);
            out.push(b.text(&r.destruction)?);
            out.push(b.text(&r.address.0)?);
            out.push(b.array(2, |b, v| {
                let (n, d) = r.amount.exact().split_once('/').unwrap_or((r.amount.exact(), "1"));
                v.push(b.array(2, |b, v| {
                    v.push(b.text(n)?);
                    v.push(b.text(d)?);
                    Ok(())
                })?);
                v.push(b.text(r.amount.unit())?);
                Ok(())
            })?);
            Ok(())
        })
    }
    fn marker(
        &mut self,
        input: &Input<'_>,
        m: &burn::RecognizedMarker,
        base: Option<&burn::RecognizedMarker>,
    ) -> Result<Value, Error> {
        let marker = m.identity();
        self.array(12, |b, out| {
            for value in scope(marker) {
                out.push(b.text(value)?);
            }
            out.push(Value::Unsigned(marker.index));
            out.push(Value::Unsigned(marker.history_position));
            out.push(marker.predecessor.map_or(Value::Null, Value::Unsigned));
            let count = marker
                .lineage
                .iter()
                .filter(|v| base.is_none_or(|p| !p.identity().lineage.contains(*v)))
                .count();
            out.push(b.array(count, |b, v| {
                for id in marker
                    .lineage
                    .iter()
                    .filter(|v| base.is_none_or(|p| !p.identity().lineage.contains(*v)))
                {
                    v.push(b.record(record(&input.frame.marker_history, id)?)?);
                }
                Ok(())
            })?);
            out.push(match &marker.accepted {
                burn::AcceptedSet::CompleteList(members) => b.array(2, |b, v| {
                    v.push(Value::Unsigned(0));
                    v.push(b.set(members, base.map(burn::RecognizedMarker::accepted))?);
                    Ok(())
                })?,
                burn::AcceptedSet::Commitment { commitment, .. } => b.array(2, |b, v| {
                    v.push(Value::Unsigned(1));
                    v.push(b.bytes(commitment)?);
                    Ok(())
                })?,
                burn::AcceptedSet::WholePrefix => b.array(1, |_, v| {
                    v.push(Value::Unsigned(2));
                    Ok(())
                })?,
            });
            out.push(b.set(m.accepted(), base.map(burn::RecognizedMarker::accepted))?);
            out.push(if marker.index == 0 {
                Value::Map(Map::take_empty_reserved(&mut Vec::new())?)
            } else {
                Value::Null
            });
            out.push(Value::Null); // Neither transition is expressible by the current admitted carrier.
            Ok(())
        })
    }
    fn projection(&mut self, input: &Input<'_>, previous: Option<&Input<'_>>, parent: Option<&[u8; 32]>) -> Result<Owned, Error> {
        Ok(Owned(Some(self.array(2, |b, out| {
            out.push(b.text(TAG)?);
            out.push(b.array(3, |b, v| {
                v.push(if parent.is_some() {
                    Value::Null
                } else {
                    b.array(4, |b, v| {
                        v.push(b.array(4, |b, v| {
                            for s in scope(input.initial.identity()) {
                                v.push(b.text(s)?);
                            }
                            Ok(())
                        })?);
                        v.push(b.declaration(input.genesis)?);
                        v.push(b.policy(&input.frame.marker_policy)?);
                        v.push(b.marker(input, input.initial, None)?);
                        Ok(())
                    })?
                });
                v.push(match parent {
                    Some(id) => b.bytes(id)?,
                    None => Value::Null,
                });
                v.push(b.marker(input, input.terminal, Some(previous.map_or(input.initial, |p| p.terminal)))?);
                Ok(())
            })?);
            Ok(())
        })?)))
    }
    fn preimage(&mut self, input: &Input<'_>, previous: Option<&Input<'_>>, parent: Option<&[u8; 32]>) -> Result<Vec<u8>, Error> {
        let value = self.projection(input, previous, parent)?;
        self.encode(&value)
    }
    fn encode(&mut self, value: &Owned) -> Result<Vec<u8>, Error> {
        let value = value.0.as_ref().ok_or(Error::InvalidPosition)?;
        let remaining = self
            .ceiling
            .checked_sub(self.usage.allocation_bytes)
            .ok_or(EncodingError::Limit)?;
        let usage = CombinedUsage {
            calls: self.usage.allocation_calls,
            bytes: self.usage.allocation_bytes,
            output: self.usage,
        };
        value
            .to_canonical_bytes_budgeted(remaining, usage.output, &mut self.reservation)
            .map_err(Error::from)
    }
}
