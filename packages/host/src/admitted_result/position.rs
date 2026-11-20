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

/// Project strict stored spans with the same field selection and builder as admitted input.
/// The caller retains the snapshot, charges every reservation and compares the residue.
pub(crate) fn from_stored_spans(
    document: &StoredDocument<'_>,
    parent: Option<(&StoredDocument<'_>, &[u8; 32])>,
    ceiling: usize,
    usage: &mut EncodingUsage,
    reservation: &mut dyn FnMut(usize) -> Result<(), ()>,
) -> Result<([u8; 32], Value, Vec<u8>), Error> {
    *usage = EncodingUsage::default();
    let input = ProjectionFields::validated(document)?;
    let previous = parent
        .map(|(document, _)| ProjectionFields::validated(document))
        .transpose()?;
    let mut builder = Builder {
        ceiling,
        usage,
        reservation,
    };
    let (bytes, context) = builder.preimage_fields(&input, previous.as_ref(), parent.map(|(_, id)| id))?;
    let residue = crate::storage::digest(RECIPE, &bytes);
    Ok((residue, context, bytes))
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
    pub(crate) fn audit_context(
        &self,
        ceiling: usize,
        usage: &mut EncodingUsage,
        reservation: &mut dyn FnMut(usize) -> Result<(), ()>,
    ) -> Result<Value, Error> {
        let mut builder = Builder {
            ceiling,
            usage,
            reservation,
        };
        builder.context(
            &self.context.genesis,
            &self.context.policy,
            &self.context.initial,
            &self.context.records,
        )
    }

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

// The selection rule is shared by admitted fields now and validated stored fields later.
// Accessors expose fields; they cannot choose a frame, marker or genesis declaration.
trait PositionFieldView {
    type Frame: Copy;
    type Marker: Copy;
    type Declaration: Copy;

    fn frame_count(&self) -> usize;
    fn frame(&self, at: usize) -> Option<Self::Frame>;
    fn marker_count(&self, frame: Self::Frame) -> usize;
    fn marker(&self, frame: Self::Frame, at: usize) -> Option<Self::Marker>;
    fn boundary(&self, frame: Self::Frame) -> u64;
    fn marker_index(&self, marker: Self::Marker) -> u64;
    fn declaration_count(&self) -> usize;
    fn declaration(&self, at: usize) -> Option<Self::Declaration>;
    fn is_genesis(&self, declaration: Self::Declaration) -> bool;
    fn genesis_at(&self, declaration: Self::Declaration) -> Option<u64>;
    fn policy_genesis_at(&self, frame: Self::Frame) -> u64;
}

struct SelectedFields<F, M, D> {
    frame: F,
    initial: M,
    terminal: M,
    genesis: D,
}

type SelectedFrom<V> =
    SelectedFields<<V as PositionFieldView>::Frame, <V as PositionFieldView>::Marker, <V as PositionFieldView>::Declaration>;

fn select_fields<V: PositionFieldView>(view: &V) -> Result<SelectedFrom<V>, Error> {
    let frame = view
        .frame_count()
        .checked_sub(1)
        .and_then(|at| view.frame(at))
        .ok_or(Error::InvalidPosition)?;
    let initial = view.marker(frame, 0).ok_or(Error::InvalidPosition)?;
    let mut terminal = None;
    for at in 0..view.marker_count(frame) {
        let marker = view.marker(frame, at).ok_or(Error::InvalidPosition)?;
        if view.marker_index(marker) == view.boundary(frame) {
            terminal = Some(marker);
            break;
        }
    }
    let terminal = terminal.ok_or(Error::InvalidPosition)?;
    let mut genesis = None;
    for at in 0..view.declaration_count() {
        let declaration = view.declaration(at).ok_or(Error::InvalidPosition)?;
        if view.is_genesis(declaration) && genesis.replace(declaration).is_some() {
            return Err(Error::InvalidPosition);
        }
    }
    let genesis = genesis.ok_or(Error::InvalidPosition)?;
    if view.genesis_at(genesis) != Some(view.policy_genesis_at(frame)) {
        return Err(Error::InvalidPosition);
    }
    Ok(SelectedFields {
        frame,
        initial,
        terminal,
        genesis,
    })
}

struct AdmittedFields<'a>(&'a pn_epoch::publication::Carrier);

type StoredItem<'a> = crate::storage::tree::server::spans::Item<'a>;
type StoredDocument<'a> = crate::storage::tree::server::spans::Validated<'a>;

struct StoredFields<'a> {
    document: &'a StoredDocument<'a>,
}

impl<'a> StoredFields<'a> {
    fn frames(&self) -> Option<StoredItem<'a>> {
        self.document.root().ok()?.map_value(8).ok()?.field(3).ok()
    }
    fn declarations(&self) -> Option<StoredItem<'a>> {
        self.document.root().ok()?.map_value(8).ok()?.field(0).ok()
    }
}

impl<'a> PositionFieldView for StoredFields<'a> {
    type Frame = StoredItem<'a>;
    type Marker = StoredItem<'a>;
    type Declaration = StoredItem<'a>;

    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn frame_count(&self) -> usize {
        self.frames().and_then(|v| v.children().ok()).map_or(0, Iterator::count)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn frame(&self, at: usize) -> Option<Self::Frame> {
        self.frames()?.children().ok()?.nth(at)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn marker_count(&self, frame: Self::Frame) -> usize {
        frame
            .field(7)
            .ok()
            .and_then(|v| v.field(1).ok())
            .and_then(|v| v.children().ok())
            .map_or(0, Iterator::count)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn marker(&self, frame: Self::Frame, at: usize) -> Option<Self::Marker> {
        frame.field(7).ok()?.field(1).ok()?.children().ok()?.nth(at)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn boundary(&self, frame: Self::Frame) -> u64 {
        frame
            .field(2)
            .ok()
            .and_then(|v| stored_decimal(v, 0).ok())
            .unwrap_or(u64::MAX)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn marker_index(&self, marker: Self::Marker) -> u64 {
        marker
            .field(0)
            .ok()
            .and_then(|v| stored_decimal(v, 5).ok())
            .unwrap_or(u64::MAX)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn declaration_count(&self) -> usize {
        self.declarations().and_then(|v| v.children().ok()).map_or(0, Iterator::count)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn declaration(&self, at: usize) -> Option<Self::Declaration> {
        self.declarations()?.children().ok()?.nth(at)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn is_genesis(&self, declaration: Self::Declaration) -> bool {
        declaration.field(0).and_then(|v| v.field(0)).and_then(StoredItem::text).ok() == Some("deployment")
            && declaration.field(0).and_then(|v| v.field(1)).and_then(StoredItem::text).ok() == Some("genesis")
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn genesis_at(&self, declaration: Self::Declaration) -> Option<u64> {
        declaration.field(3).ok().and_then(|v| stored_decimal(v, 1).ok())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn policy_genesis_at(&self, frame: Self::Frame) -> u64 {
        frame
            .field(5)
            .ok()
            .and_then(|v| stored_decimal(v, 4).ok())
            .unwrap_or(u64::MAX)
    }
}

impl<'a> PositionFieldView for AdmittedFields<'a> {
    type Frame = &'a Frame;
    type Marker = &'a burn::RecognizedMarker;
    type Declaration = &'a Declaration;

    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn frame_count(&self) -> usize {
        self.0.frames.len()
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn frame(&self, at: usize) -> Option<Self::Frame> {
        self.0.frames.get(at)
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn marker_count(&self, frame: Self::Frame) -> usize {
        frame.closure.markers.markers().len()
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn marker(&self, frame: Self::Frame, at: usize) -> Option<Self::Marker> {
        frame.closure.markers.markers().get(at)
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn boundary(&self, frame: Self::Frame) -> u64 {
        frame.parameters.boundary
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn marker_index(&self, marker: Self::Marker) -> u64 {
        marker.identity().index
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn declaration_count(&self) -> usize {
        self.0.causes.declarations.len()
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn declaration(&self, at: usize) -> Option<Self::Declaration> {
        self.0.causes.declarations.get(at)
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn is_genesis(&self, declaration: Self::Declaration) -> bool {
        declaration.id.namespace == "deployment" && declaration.id.name == "genesis"
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn genesis_at(&self, declaration: Self::Declaration) -> Option<u64> {
        if let DeclarationContent::Deployment { genesis_at } = declaration.content {
            Some(genesis_at)
        } else {
            None
        }
    }
    /// Justified: Private admitted field access inherits observed position construction or retention.
    fn policy_genesis_at(&self, frame: Self::Frame) -> u64 {
        frame.marker_policy.genesis_at
    }
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
        let SelectedFields {
            frame,
            initial,
            terminal,
            genesis,
        } = select_fields(&AdmittedFields(carrier))?;
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

#[derive(Clone, Copy)]
enum PolicyFields<'a> {
    Admitted(&'a burn::PolicyInput),
    Stored(StoredItem<'a>),
}
#[derive(Clone, Copy)]
enum DeclarationFields<'a> {
    Admitted(&'a Declaration),
    Stored(StoredItem<'a>),
}
#[derive(Clone, Copy)]
enum RecordFields<'a> {
    Admitted(&'a burn::BurnRecord),
    Stored(StoredItem<'a>),
}
#[derive(Clone, Copy)]
enum RecordsFields<'a> {
    Admitted(&'a [burn::BurnRecord]),
    Stored(StoredItem<'a>),
}
#[derive(Clone, Copy)]
enum MarkerFields<'a> {
    Admitted(&'a burn::RecognizedMarker),
    Stored(StoredItem<'a>),
}
#[derive(Clone, Copy)]
struct ProjectionFields<'a> {
    genesis: DeclarationFields<'a>,
    policy: PolicyFields<'a>,
    initial: MarkerFields<'a>,
    terminal: MarkerFields<'a>,
    records: RecordsFields<'a>,
}

fn stored<T>(result: Result<T, crate::storage::tree::Error>) -> Result<T, Error> {
    result.map_err(|_| Error::InvalidPosition)
}

fn stored_text(item: StoredItem<'_>, at: usize) -> Result<&str, Error> {
    stored(item.field(at).and_then(StoredItem::text))
}
fn stored_decimal(item: StoredItem<'_>, at: usize) -> Result<u64, Error> {
    let value = stored(item.field(at))?;
    if let Ok(number) = value.unsigned() {
        return Ok(number);
    }
    value
        .text()
        .map_err(|_| Error::InvalidPosition)?
        .parse()
        .map_err(|_| Error::InvalidPosition)
}

fn stored_sorted_text_at(item: StoredItem<'_>, at: usize) -> Result<&str, Error> {
    let mut previous = None;
    for _ in 0..=at {
        let mut next = None;
        for candidate in stored(item.children())? {
            let text = stored(candidate.text())?;
            if previous.is_none_or(|before| text > before) && next.is_none_or(|after| text < after) {
                next = Some(text);
            }
        }
        previous = Some(next.ok_or(Error::InvalidPosition)?);
    }
    previous.ok_or(Error::InvalidPosition)
}

impl<'a> PolicyFields<'a> {
    fn text(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(p) => match at {
                0 => Ok(&p.identity),
                1 => Ok(&p.edition),
                2 => Ok(&p.sequence),
                5 => Ok(&p.initial_marker),
                7 => Ok(&p.placement_procedure),
                8 => Ok(&p.cadence),
                11 => Ok(&p.verification_profile),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(p) => stored_text(p, at),
        }
    }
    fn number(self, at: usize) -> Result<u64, Error> {
        match self {
            Self::Admitted(p) => match at {
                3 => Ok(p.published_at),
                4 => Ok(p.genesis_at),
                12 => Ok(p.stability_buffer),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(p) => stored_decimal(p, at),
        }
    }
    fn open(self) -> Result<bool, Error> {
        match self {
            Self::Admitted(p) => Ok(p.open_placement),
            Self::Stored(p) => {
                let value = stored(p.field(6))?;
                match value.bytes() {
                    [0xf4] => Ok(false),
                    [0xf5] => Ok(true),
                    _ => Err(Error::InvalidPosition),
                }
            }
        }
    }
    fn encoding(self) -> Result<u64, Error> {
        match self {
            Self::Admitted(p) => Ok(match p.encoding {
                burn::Encoding::CompleteList => 0,
                burn::Encoding::PublicCommitment => 1,
                burn::Encoding::WholePrefixAcceptAll => 2,
            }),
            Self::Stored(p) => {
                let tag = stored(stored(p.field(9))?.field(0).and_then(StoredItem::unsigned))?;
                if tag > 2 { Err(Error::InvalidPosition) } else { Ok(tag) }
            }
        }
    }
    fn candidate(self) -> Result<u64, Error> {
        match self {
            Self::Admitted(p) => Ok(match p.candidate_rule {
                burn::CandidateRule::FirstValidInHistoryOrder => 0,
                burn::CandidateRule::UniquePerIndex => 1,
            }),
            Self::Stored(p) => {
                let tag = stored(stored(p.field(10))?.field(0).and_then(StoredItem::unsigned))?;
                if tag > 1 { Err(Error::InvalidPosition) } else { Ok(tag) }
            }
        }
    }
}

impl<'a> DeclarationFields<'a> {
    fn id(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(d) => match at {
                0 => Ok(&d.id.namespace),
                1 => Ok(&d.id.name),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(d) => stored_text(stored(d.field(0))?, at),
        }
    }
    fn number(self, at: usize) -> Result<u64, Error> {
        match self {
            Self::Admitted(d) => match at {
                0 => Ok(d.id.edition),
                1 => Ok(d.announced_at),
                2 => Ok(d.effective_at),
                3 => match d.content {
                    DeclarationContent::Deployment { genesis_at } => Ok(genesis_at),
                    _ => Err(Error::InvalidPosition),
                },
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(d) => match at {
                0 => stored_decimal(stored(d.field(0))?, 2),
                1 | 2 => stored_decimal(d, at),
                3 => {
                    let content = stored(d.field(3))?;
                    if stored(content.field(0).and_then(StoredItem::unsigned))? != 1 {
                        return Err(Error::InvalidPosition);
                    }
                    stored_decimal(content, 1)
                }
                _ => Err(Error::InvalidPosition),
            },
        }
    }
}

impl<'a> RecordFields<'a> {
    fn rational(self) -> Result<(&'a str, &'a str), Error> {
        match self {
            Self::Admitted(record) => {
                let exact = record.amount.exact();
                Ok(exact.split_once('/').unwrap_or((exact, "1")))
            }
            Self::Stored(record) => {
                let amount = stored(record.field(3).and_then(|v| v.field(0)))?;
                Ok((stored_text(amount, 0)?, stored_text(amount, 1)?))
            }
        }
    }
    fn text(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(r) => match at {
                0 => Ok(&r.identity),
                1 => Ok(&r.destruction),
                2 => Ok(&r.address.0),
                4 => Ok(r.amount.unit()),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(r) => match at {
                0..=2 => stored_text(r, at),
                4 => stored_text(stored(r.field(3))?, 1),
                _ => Err(Error::InvalidPosition),
            },
        }
    }
}

impl<'a> RecordsFields<'a> {
    fn find(self, identity: &str) -> Result<RecordFields<'a>, Error> {
        let mut found = None;
        match self {
            Self::Admitted(records) => {
                for record in records {
                    if record.identity == identity && found.replace(RecordFields::Admitted(record)).is_some() {
                        return Err(Error::InvalidPosition);
                    }
                }
            }
            Self::Stored(records) => {
                for record in stored(records.children())? {
                    if stored_text(record, 0)? == identity && found.replace(RecordFields::Stored(record)).is_some() {
                        return Err(Error::InvalidPosition);
                    }
                }
            }
        }
        found.ok_or(Error::InvalidPosition)
    }
}

impl<'a> MarkerFields<'a> {
    fn identity(self) -> Result<StoredItem<'a>, Error> {
        match self {
            Self::Stored(marker) => stored(marker.field(0)),
            Self::Admitted(_) => Err(Error::InvalidPosition),
        }
    }
    fn text(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(marker) => {
                let id = marker.identity();
                match at {
                    0 => Ok(&id.name),
                    1 => Ok(&id.history),
                    2 => Ok(&id.policy_identity),
                    3 => Ok(&id.policy_edition),
                    4 => Ok(&id.sequence),
                    _ => Err(Error::InvalidPosition),
                }
            }
            Self::Stored(_) => stored_text(self.identity()?, at),
        }
    }
    fn number(self, at: usize) -> Result<u64, Error> {
        match self {
            Self::Admitted(marker) => match at {
                5 => Ok(marker.identity().index),
                6 => Ok(marker.identity().history_position),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(_) => stored_decimal(self.identity()?, at),
        }
    }
    fn predecessor(self) -> Result<Option<u64>, Error> {
        match self {
            Self::Admitted(marker) => Ok(marker.identity().predecessor),
            Self::Stored(_) => {
                let value = stored(self.identity()?.field(7))?;
                if value.null() {
                    Ok(None)
                } else {
                    value
                        .text()
                        .map_err(|_| Error::InvalidPosition)?
                        .parse()
                        .map(Some)
                        .map_err(|_| Error::InvalidPosition)
                }
            }
        }
    }
    fn lineage_count(self) -> Result<usize, Error> {
        match self {
            Self::Admitted(marker) => Ok(marker.identity().lineage.len()),
            Self::Stored(_) => Ok(stored(self.identity()?.field(8).and_then(StoredItem::children))?.count()),
        }
    }
    fn lineage_at(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(marker) => marker
                .identity()
                .lineage
                .iter()
                .nth(at)
                .map(String::as_str)
                .ok_or(Error::InvalidPosition),
            Self::Stored(_) => stored_sorted_text_at(stored(self.identity()?.field(8))?, at),
        }
    }
    fn accepted_count(self) -> Result<usize, Error> {
        match self {
            Self::Admitted(marker) => Ok(marker.accepted().len()),
            Self::Stored(marker) => Ok(stored(marker.field(1).and_then(StoredItem::children))?.count()),
        }
    }
    fn accepted_at(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(marker) => marker
                .accepted()
                .iter()
                .nth(at)
                .map(String::as_str)
                .ok_or(Error::InvalidPosition),
            Self::Stored(marker) => stored_sorted_text_at(stored(marker.field(1))?, at),
        }
    }
    fn contains_lineage(self, value: &str) -> Result<bool, Error> {
        for at in 0..self.lineage_count()? {
            if self.lineage_at(at)? == value {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn contains_accepted(self, value: &str) -> Result<bool, Error> {
        for at in 0..self.accepted_count()? {
            if self.accepted_at(at)? == value {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn accepted_kind(self) -> Result<u64, Error> {
        match self {
            Self::Admitted(marker) => Ok(match marker.identity().accepted {
                burn::AcceptedSet::CompleteList(_) => 0,
                burn::AcceptedSet::Commitment { .. } => 1,
                burn::AcceptedSet::WholePrefix => 2,
            }),
            Self::Stored(_) => {
                let tag = stored(
                    self.identity()?
                        .field(9)
                        .and_then(|v| v.field(0))
                        .and_then(StoredItem::unsigned),
                )?;
                if tag > 2 { Err(Error::InvalidPosition) } else { Ok(tag) }
            }
        }
    }
    fn accepted_variant_count(self) -> Result<usize, Error> {
        match self {
            Self::Admitted(marker) => match &marker.identity().accepted {
                burn::AcceptedSet::CompleteList(members) => Ok(members.len()),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(_) => Ok(stored(
                self.identity()?
                    .field(9)
                    .and_then(|v| v.field(1))
                    .and_then(StoredItem::children),
            )?
            .count()),
        }
    }
    fn accepted_variant_at(self, at: usize) -> Result<&'a str, Error> {
        match self {
            Self::Admitted(marker) => match &marker.identity().accepted {
                burn::AcceptedSet::CompleteList(members) => {
                    members.iter().nth(at).map(String::as_str).ok_or(Error::InvalidPosition)
                }
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(_) => stored_sorted_text_at(stored(self.identity()?.field(9).and_then(|v| v.field(1)))?, at),
        }
    }
    fn commitment(self) -> Result<&'a [u8], Error> {
        match self {
            Self::Admitted(marker) => match &marker.identity().accepted {
                burn::AcceptedSet::Commitment { commitment, .. } => Ok(commitment),
                _ => Err(Error::InvalidPosition),
            },
            Self::Stored(_) => stored(self.identity()?.field(9).and_then(|v| v.field(1)).and_then(StoredItem::blob)),
        }
    }
    fn initial_snapshot_empty(self) -> Result<bool, Error> {
        match self {
            Self::Admitted(marker) => Ok(marker
                .identity()
                .initial_snapshot
                .as_ref()
                .is_some_and(std::collections::BTreeMap::is_empty)),
            Self::Stored(_) => {
                let value = stored(self.identity()?.field(10))?;
                Ok(!value.null() && stored(value.children())?.next().is_none())
            }
        }
    }
}

impl<'a> ProjectionFields<'a> {
    fn admitted(input: &Input<'a>) -> Self {
        Self {
            genesis: DeclarationFields::Admitted(input.genesis),
            policy: PolicyFields::Admitted(&input.frame.marker_policy),
            initial: MarkerFields::Admitted(input.initial),
            terminal: MarkerFields::Admitted(input.terminal),
            records: RecordsFields::Admitted(&input.frame.marker_history.records),
        }
    }
    fn validated(document: &'a StoredDocument<'a>) -> Result<Self, Error> {
        let SelectedFields {
            frame,
            initial,
            terminal,
            genesis,
        } = select_fields(&StoredFields { document })?;
        Ok(Self {
            genesis: DeclarationFields::Stored(genesis),
            policy: PolicyFields::Stored(stored(frame.field(5))?),
            initial: MarkerFields::Stored(initial),
            terminal: MarkerFields::Stored(terminal),
            records: RecordsFields::Stored(stored(frame.field(6).and_then(|v| v.field(1)))?),
        })
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
    fn set_fields(&mut self, marker: MarkerFields<'_>, base: Option<MarkerFields<'_>>, variant: bool) -> Result<Value, Error> {
        let length = if variant {
            marker.accepted_variant_count()?
        } else {
            marker.accepted_count()?
        };
        let mut count = 0;
        for at in 0..length {
            let value = if variant {
                marker.accepted_variant_at(at)?
            } else {
                marker.accepted_at(at)?
            };
            if base
                .map(|prior| prior.contains_accepted(value))
                .transpose()?
                .is_none_or(|contained| !contained)
            {
                count += 1;
            }
        }
        self.array(count, |b, out| {
            for at in 0..length {
                let value = if variant {
                    marker.accepted_variant_at(at)?
                } else {
                    marker.accepted_at(at)?
                };
                if base
                    .map(|prior| prior.contains_accepted(value))
                    .transpose()?
                    .is_none_or(|contained| !contained)
                {
                    out.push(b.text(value)?);
                }
            }
            Ok(())
        })
    }
    #[cfg(test)]
    fn policy(&mut self, p: &burn::PolicyInput) -> Result<Value, Error> {
        self.policy_fields(PolicyFields::Admitted(p))
    }
    fn policy_fields(&mut self, p: PolicyFields<'_>) -> Result<Value, Error> {
        self.array(13, |b, out| {
            for at in 0..3 {
                out.push(b.text(p.text(at)?)?);
            }
            out.push(b.decimal(p.number(3)?)?);
            out.push(b.decimal(p.number(4)?)?);
            out.push(b.text(p.text(5)?)?);
            out.push(Value::Bool(p.open()?));
            out.push(b.text(p.text(7)?)?);
            out.push(b.text(p.text(8)?)?);
            let encoding = p.encoding()?;
            out.push(b.array(1, |_, v| {
                v.push(Value::Unsigned(encoding));
                Ok(())
            })?);
            let candidate = p.candidate()?;
            out.push(b.array(1, |_, v| {
                v.push(Value::Unsigned(candidate));
                Ok(())
            })?);
            out.push(b.text(p.text(11)?)?);
            out.push(b.decimal(p.number(12)?)?);
            Ok(())
        })
    }
    #[cfg(test)]
    fn declaration(&mut self, d: &Declaration) -> Result<Value, Error> {
        self.declaration_fields(DeclarationFields::Admitted(d))
    }
    fn declaration_fields(&mut self, d: DeclarationFields<'_>) -> Result<Value, Error> {
        self.array(4, |b, out| {
            out.push(b.array(3, |b, v| {
                v.push(b.text(d.id(0)?)?);
                v.push(b.text(d.id(1)?)?);
                v.push(b.decimal(d.number(0)?)?);
                Ok(())
            })?);
            out.push(b.decimal(d.number(1)?)?);
            out.push(b.decimal(d.number(2)?)?);
            out.push(b.array(2, |b, v| {
                v.push(Value::Unsigned(1));
                v.push(b.decimal(d.number(3)?)?);
                Ok(())
            })?);
            Ok(())
        })
    }
    #[cfg(test)]
    fn record(&mut self, r: &burn::BurnRecord) -> Result<Value, Error> {
        self.record_fields(RecordFields::Admitted(r))
    }
    fn record_fields(&mut self, r: RecordFields<'_>) -> Result<Value, Error> {
        self.array(4, |b, out| {
            out.push(b.text(r.text(0)?)?);
            out.push(b.text(r.text(1)?)?);
            out.push(b.text(r.text(2)?)?);
            out.push(b.array(2, |b, v| {
                let (n, d) = r.rational()?;
                v.push(b.array(2, |b, v| {
                    v.push(b.text(n)?);
                    v.push(b.text(d)?);
                    Ok(())
                })?);
                v.push(b.text(r.text(4)?)?);
                Ok(())
            })?);
            Ok(())
        })
    }
    fn marker_fields(
        &mut self,
        records: RecordsFields<'_>,
        marker: MarkerFields<'_>,
        base: Option<MarkerFields<'_>>,
    ) -> Result<Value, Error> {
        self.array(12, |b, out| {
            for at in 1..=4 {
                out.push(b.text(marker.text(at)?)?);
            }
            out.push(Value::Unsigned(marker.number(5)?));
            out.push(Value::Unsigned(marker.number(6)?));
            out.push(marker.predecessor()?.map_or(Value::Null, Value::Unsigned));
            let length = marker.lineage_count()?;
            let mut count = 0;
            for at in 0..length {
                let value = marker.lineage_at(at)?;
                if base
                    .map(|prior| prior.contains_lineage(value))
                    .transpose()?
                    .is_none_or(|contained| !contained)
                {
                    count += 1;
                }
            }
            out.push(b.array(count, |b, v| {
                for at in 0..length {
                    let identity = marker.lineage_at(at)?;
                    if base
                        .map(|prior| prior.contains_lineage(identity))
                        .transpose()?
                        .is_none_or(|contained| !contained)
                    {
                        v.push(b.record_fields(records.find(identity)?)?);
                    }
                }
                Ok(())
            })?);
            out.push(match marker.accepted_kind()? {
                0 => b.array(2, |b, v| {
                    v.push(Value::Unsigned(0));
                    v.push(b.set_fields(marker, base, true)?);
                    Ok(())
                })?,
                1 => b.array(2, |b, v| {
                    v.push(Value::Unsigned(1));
                    v.push(b.bytes(marker.commitment()?)?);
                    Ok(())
                })?,
                2 => b.array(1, |_, v| {
                    v.push(Value::Unsigned(2));
                    Ok(())
                })?,
                _ => return Err(Error::InvalidPosition),
            });
            out.push(b.set_fields(marker, base, false)?);
            out.push(if marker.number(5)? == 0 && marker.initial_snapshot_empty()? {
                Value::Map(Map::take_empty_reserved(&mut Vec::new())?)
            } else {
                Value::Null
            });
            out.push(Value::Null); // Neither transition is expressible by the current admitted carrier.
            Ok(())
        })
    }
    fn context(
        &mut self,
        genesis: &Declaration,
        policy: &burn::PolicyInput,
        initial: &burn::RecognizedMarker,
        records: &[burn::BurnRecord],
    ) -> Result<Value, Error> {
        self.context_fields(&ProjectionFields {
            genesis: DeclarationFields::Admitted(genesis),
            policy: PolicyFields::Admitted(policy),
            initial: MarkerFields::Admitted(initial),
            terminal: MarkerFields::Admitted(initial),
            records: RecordsFields::Admitted(records),
        })
    }
    fn context_fields(&mut self, input: &ProjectionFields<'_>) -> Result<Value, Error> {
        self.array(4, |b, v| {
            v.push(b.array(4, |b, v| {
                for at in 1..=4 {
                    v.push(b.text(input.initial.text(at)?)?);
                }
                Ok(())
            })?);
            v.push(b.declaration_fields(input.genesis)?);
            v.push(b.policy_fields(input.policy)?);
            v.push(b.marker_fields(input.records, input.initial, None)?);
            Ok(())
        })
    }
    fn projection(&mut self, input: &Input<'_>, previous: Option<&Input<'_>>, parent: Option<&[u8; 32]>) -> Result<Owned, Error> {
        self.projection_fields(
            &ProjectionFields::admitted(input),
            previous.as_ref().map(|input| ProjectionFields::admitted(input)).as_ref(),
            parent,
        )
    }
    fn projection_fields(
        &mut self,
        input: &ProjectionFields<'_>,
        previous: Option<&ProjectionFields<'_>>,
        parent: Option<&[u8; 32]>,
    ) -> Result<Owned, Error> {
        Ok(Owned(Some(self.array(2, |b, out| {
            out.push(b.text(TAG)?);
            out.push(b.array(3, |b, v| {
                v.push(if parent.is_some() {
                    Value::Null
                } else {
                    b.context_fields(input)?
                });
                v.push(match parent {
                    Some(id) => b.bytes(id)?,
                    None => Value::Null,
                });
                v.push(b.marker_fields(
                    input.records,
                    input.terminal,
                    Some(previous.map_or(input.initial, |p| p.terminal)),
                )?);
                Ok(())
            })?);
            Ok(())
        })?)))
    }
    fn preimage(&mut self, input: &Input<'_>, previous: Option<&Input<'_>>, parent: Option<&[u8; 32]>) -> Result<Vec<u8>, Error> {
        let value = self.projection(input, previous, parent)?;
        self.encode(&value)
    }
    fn preimage_fields(
        &mut self,
        input: &ProjectionFields<'_>,
        previous: Option<&ProjectionFields<'_>>,
        parent: Option<&[u8; 32]>,
    ) -> Result<(Vec<u8>, Value), Error> {
        let value = self.projection_fields(input, previous, parent)?;
        let bytes = self.encode(&value)?;
        let context = self.context_fields(input)?;
        Ok((bytes, context))
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
