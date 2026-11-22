//! Immutable successor acts and opening evidence supplied beside them.
//! Equality of a carrier does not establish signature validity or inclusion.
//! (´[ROOT-amend:identity:closure-components]´)

use std::collections::{BTreeMap, BTreeSet};

use crate::commitments::ActCommitments;
use crate::{
    ActId, DependencyCause, DependencyViolation, EdgeId, InvalidCause, Layout, ParentPlacementFault, PublicReference, Role,
    SettlementReferences, StructuralBody, StructuralInput, TimeEvidence, ValidationError, check_times_structural, mints,
    parent_faults_structural, valid_reference, validate_order,
};

/// A borrowed structural edge from the same checked header as its body.
#[derive(Clone, Copy, Debug)]
pub struct ClosureLeg<'a> {
    pub id: &'a EdgeId,
    pub source: &'a PublicReference,
    pub target: &'a PublicReference,
}

/// A consistent, borrowed projection of one checked canonical header.
/// Implementations must derive every member from the same retained header;
/// records checks structure but makes no cryptographic assertion.
pub trait ClosureHeader: Clone + std::fmt::Debug {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> &ActId;
    fn body(&self) -> &StructuralBody;
    fn legs(&self) -> Vec<ClosureLeg<'_>>;
    fn protocol_references(&self) -> &[PublicReference];
    fn commitments(&self) -> &ActCommitments;
}

/// Exact retained successor value, without a dependency list or holder state.
#[derive(Clone, Debug)]
pub struct ClosureAct<H: ClosureHeader> {
    header: H,
    material: Vec<u8>,
    host_seal: [u8; 64],
    actor_approval: [u8; 64],
    epoch: u64,
    position: u64,
    logical_time: u64,
}

impl<H: ClosureHeader> ClosureAct<H> {
    /// Construct an unchecked representation. Fragment and history admission are separate.
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-new",
            source_item = "closure::ClosureAct < H >::new"
        ),
        ret
    )]
    pub fn new(
        header: H,
        material: Vec<u8>,
        host_seal: [u8; 64],
        actor_approval: [u8; 64],
        epoch: u64,
        position: u64,
        logical_time: u64,
    ) -> Self {
        Self {
            header,
            material,
            host_seal,
            actor_approval,
            epoch,
            position,
            logical_time,
        }
    }

    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-header",
            source_item = "closure::ClosureAct < H >::header"
        ),
        ret
    )]
    pub fn header(&self) -> &H {
        &self.header
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-material",
            source_item = "closure::ClosureAct < H >::material"
        ),
        ret
    )]
    pub fn material(&self) -> &[u8] {
        &self.material
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-host-seal",
            source_item = "closure::ClosureAct < H >::host_seal"
        ),
        ret
    )]
    pub fn host_seal(&self) -> &[u8; 64] {
        &self.host_seal
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-actor-approval",
            source_item = "closure::ClosureAct < H >::actor_approval"
        ),
        ret
    )]
    pub fn actor_approval(&self) -> &[u8; 64] {
        &self.actor_approval
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-epoch",
            source_item = "closure::ClosureAct < H >::epoch"
        ),
        ret
    )]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-position",
            source_item = "closure::ClosureAct < H >::position"
        ),
        ret
    )]
    pub fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-logical-time",
            source_item = "closure::ClosureAct < H >::logical_time"
        ),
        ret
    )]
    pub fn logical_time(&self) -> u64 {
        self.logical_time
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closureact-h-id",
            source_item = "closure::ClosureAct < H >::id"
        ),
        ret
    )]
    pub fn id(&self) -> &ActId {
        self.header.id()
    }

    fn structural<'a>(&'a self, dependencies: Option<&'a [ActId]>) -> StructuralInput<'a> {
        StructuralInput {
            id: self.header.id(),
            body: self.header.body(),
            endpoints: self.header.legs().iter().map(|leg| (leg.source, leg.target)).collect(),
            dependencies,
            position: (self.epoch, self.position),
            logical_time: self.logical_time,
        }
    }
}

/// A complete opening supplied beside, never inside, a retained closure act.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyProof {
    id: ActId,
    epoch: u64,
    position: u64,
    proposal: [u8; 32],
    dependency: [u8; 32],
    host_dependency_blinding_value: [u8; 48],
    dependencies: Vec<ActId>,
}

impl DependencyProof {
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-new",
            source_item = "closure::DependencyProof::new"
        ),
        ret
    )]
    pub fn new(
        id: ActId,
        epoch: u64,
        position: u64,
        proposal: [u8; 32],
        dependency: [u8; 32],
        host_dependency_blinding_value: [u8; 48],
        dependencies: Vec<ActId>,
    ) -> Self {
        Self {
            id,
            epoch,
            position,
            proposal,
            dependency,
            host_dependency_blinding_value,
            dependencies,
        }
    }

    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-id",
            source_item = "closure::DependencyProof::id"
        ),
        ret
    )]
    pub fn id(&self) -> &ActId {
        &self.id
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-epoch",
            source_item = "closure::DependencyProof::epoch"
        ),
        ret
    )]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-position",
            source_item = "closure::DependencyProof::position"
        ),
        ret
    )]
    pub fn position(&self) -> u64 {
        self.position
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-proposal",
            source_item = "closure::DependencyProof::proposal"
        ),
        ret
    )]
    pub fn proposal(&self) -> &[u8; 32] {
        &self.proposal
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-dependency",
            source_item = "closure::DependencyProof::dependency"
        ),
        ret
    )]
    pub fn dependency(&self) -> &[u8; 32] {
        &self.dependency
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-host-dependency-blinding-value",
            source_item = "closure::DependencyProof::host_dependency_blinding_value"
        ),
        ret
    )]
    pub fn host_dependency_blinding_value(&self) -> &[u8; 48] {
        &self.host_dependency_blinding_value
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-dependencyproof-dependencies",
            source_item = "closure::DependencyProof::dependencies"
        ),
        ret
    )]
    pub fn dependencies(&self) -> &[ActId] {
        &self.dependencies
    }
}

/// A checked finite successor history with retained public-parent faults.
#[derive(Clone, Debug)]
pub struct ClosureHistory<H: ClosureHeader> {
    acts: Vec<ClosureAct<H>>,
    indices: BTreeMap<ActId, usize>,
    references: BTreeSet<PublicReference>,
    parent_faults: Vec<ParentPlacementFault>,
}

impl<H: ClosureHeader> ClosureHistory<H> {
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closurehistory-h-acts",
            source_item = "closure::ClosureHistory < H >::acts"
        ),
        ret
    )]
    pub fn acts(&self) -> &[ClosureAct<H>] {
        &self.acts
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closurehistory-h-get",
            source_item = "closure::ClosureHistory < H >::get"
        ),
        ret
    )]
    pub fn get(&self, id: &ActId) -> Option<&ClosureAct<H>> {
        self.indices.get(id).map(|index| &self.acts[*index])
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closurehistory-h-parent-faults",
            source_item = "closure::ClosureHistory < H >::parent_faults"
        ),
        ret
    )]
    pub fn parent_faults(&self) -> &[ParentPlacementFault] {
        &self.parent_faults
    }
    #[must_use]
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "closure-closurehistory-h-references",
            source_item = "closure::ClosureHistory < H >::references"
        ),
        ret
    )]
    pub fn references(&self) -> &BTreeSet<PublicReference> {
        &self.references
    }
}

/// Validate structure and complete published order, retaining parent faults.
/// The absence of D remains unavailable and is never validated as empty.
/// # Errors
/// Refuses malformed local structure, ambiguous identity or incomplete order.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "closure-validate-history",
        source_item = "closure::validate_history"
    ),
    ret
)]
pub fn validate_history<H: ClosureHeader>(
    acts: Vec<ClosureAct<H>>,
    names: &[PublicReference],
) -> Result<ClosureHistory<H>, ValidationError> {
    let mut references = BTreeSet::new();
    for name in names {
        if !matches!(name, PublicReference::Named { .. }) || !valid_reference(name) {
            return Err(ValidationError::InvalidReference(name.clone()));
        }
        references.insert(name.clone());
    }
    let mut indices = BTreeMap::new();
    for (index, act) in acts.iter().enumerate() {
        if indices.insert(act.id().clone(), index).is_some() {
            return Err(ValidationError::DuplicateAct(act.id().clone()));
        }
        references.insert(PublicReference::Act(act.id().clone()));
        for leg in act.header.legs() {
            references.insert(PublicReference::Edge(leg.id.clone()));
            if mints(act.id(), act.header.body().layout, leg.id.role, leg.target) {
                references.insert(PublicReference::Minted(act.id().clone()));
            }
        }
    }
    for act in &acts {
        validate_structure(act, &references)?;
    }
    validate_order(acts.iter().map(|act| (act.id(), (act.epoch, act.position))))?;
    let available: BTreeMap<_, _> = acts
        .iter()
        .map(|act| (act.id(), ((act.epoch, act.position), act.logical_time)))
        .collect();
    let mut parent_faults = Vec::new();
    for act in &acts {
        parent_faults.extend(parent_faults_structural(&act.structural(None), &available)?);
    }
    Ok(ClosureHistory {
        acts,
        indices,
        references,
        parent_faults,
    })
}

fn validate_structure<H: ClosureHeader>(
    act: &ClosureAct<H>,
    references: &BTreeSet<PublicReference>,
) -> Result<(), ValidationError> {
    let id = act.id();
    let body = act.header.body();
    let invalid = |cause| ValidationError::InvalidRepresentation { act: id.clone(), cause };
    if act.epoch == 0 {
        return Err(invalid(InvalidCause::FinalizationEpoch));
    }
    if act.position == 0 {
        return Err(invalid(InvalidCause::FinalizedPosition));
    }
    if id.author.is_empty() {
        return Err(invalid(InvalidCause::EmptyAuthor));
    }
    if id.family.is_empty() {
        return Err(invalid(InvalidCause::EmptyFamily));
    }
    let settlement_ok = match (id.family.as_str(), &body.settlement) {
        ("Accept", Some(SettlementReferences::Accept { settles })) => crate::valid_id(settles),
        ("Ratify", Some(SettlementReferences::Ratify { settles, accepts })) => {
            crate::valid_id(settles) && crate::valid_id(accepts)
        }
        ("Accept" | "Ratify", _) | (_, Some(_)) => false,
        (_, None) => true,
    };
    if !settlement_ok {
        return Err(invalid(InvalidCause::SettlementReferences));
    }
    let legs = act.header.legs();
    let genesis = id.family == "Publish" && legs.iter().any(|leg| mints(id, body.layout, leg.id.role, leg.target));
    let license_ok = match body.license {
        Some(pair) => {
            genesis
                && [pair.attribution, pair.provenance]
                    .iter()
                    .all(|degree| degree.denominator > 0 && degree.numerator >= 0 && degree.numerator <= degree.denominator)
        }
        None => !genesis,
    };
    if !license_ok {
        return Err(invalid(InvalidCause::LicenseQualifiers));
    }
    let mut fields = BTreeSet::new();
    for (name, quantity) in &body.quantities {
        if name.is_empty() {
            return Err(invalid(InvalidCause::EmptyQuantityName));
        }
        if quantity.unit.is_empty() {
            return Err(invalid(InvalidCause::EmptyUnit));
        }
        if !fields.insert(name) {
            return Err(invalid(InvalidCause::DuplicateQuantityName));
        }
    }
    let required: &[Role] = match body.layout {
        Layout::Binary => &[Role::Binary],
        Layout::Paired => &[Role::A, Role::T],
    };
    let mut roles = BTreeSet::new();
    for leg in legs {
        if leg.id.act != *id {
            return Err(invalid(InvalidCause::ProjectionParent));
        }
        if !required.contains(&leg.id.role) {
            return Err(invalid(InvalidCause::ProjectionRole));
        }
        if !roles.insert(leg.id.role) {
            return Err(ValidationError::DuplicateEdge(leg.id.clone()));
        }
        for reference in [leg.source, leg.target] {
            if !valid_reference(reference) {
                return Err(invalid(InvalidCause::ReferenceComponent));
            }
            if reference.identifier_class().is_none() && !references.contains(reference) {
                return Err(ValidationError::UnresolvedReference(reference.clone()));
            }
        }
    }
    for role in required {
        if !roles.contains(role) {
            return Err(ValidationError::MissingCoLeg {
                act: id.clone(),
                role: *role,
            });
        }
    }
    for reference in act.header.protocol_references() {
        if matches!(reference, PublicReference::Named { namespace, .. } if namespace == "license") {
            return Err(invalid(InvalidCause::LicenseQualifiers));
        }
        if !valid_reference(reference) {
            return Err(invalid(InvalidCause::ReferenceComponent));
        }
        if !references.contains(reference) {
            return Err(ValidationError::UnresolvedReference(reference.clone()));
        }
    }
    Ok(())
}

/// Supplied complete dependency list, or an unavailable opening.
#[derive(Clone, Copy, Debug)]
pub enum SuppliedOpening<'a> {
    Available(&'a [ActId]),
    Unavailable,
}

/// Evidence supplied independently of the retained act and its history.
pub trait ClosureDependencyOpener<H: ClosureHeader>: std::fmt::Debug {
    fn targets(&self) -> Vec<&ActId>;
    fn opening<'a>(&'a self, act: &ClosureAct<H>) -> SuppliedOpening<'a>;
}

/// Evidence-input refusal; neither cause changes an immutable act.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpeningError {
    #[error("unknown opening target: {0:?}")]
    Unknown(ActId),
    #[error("repeated opening target: {0:?}")]
    Duplicate(ActId),
    #[error("opening list is not strictly ordered")]
    Dependencies,
}

/// Conditional observations after checking complete separately supplied lists.
#[derive(Clone, Debug)]
pub struct ClosureEvidence {
    pub time_evidence: Vec<TimeEvidence>,
    pub parent_faults: Vec<ParentPlacementFault>,
    pub dependency_violations: Vec<DependencyViolation>,
    pub unavailable_targets: BTreeSet<ActId>,
}

/// Recompute conditional time and placement evidence without mutating history.
/// # Errors
/// Refuses duplicate, unknown or noncanonical supplied evidence targets.
#[tracing::instrument(
    name = "sig:design:records",
    fields(
        execution_owner = "RECORDS",
        claim_owner = "ROOT",
        claim_label = "sig:design:records",
        operation = "closure-assess-openings",
        source_item = "closure::assess_openings"
    ),
    ret
)]
pub fn assess_openings<H: ClosureHeader>(
    history: &ClosureHistory<H>,
    openings: &impl ClosureDependencyOpener<H>,
) -> Result<ClosureEvidence, OpeningError> {
    let mut seen = BTreeSet::new();
    for target in openings.targets() {
        if history.get(target).is_none() {
            return Err(OpeningError::Unknown(target.clone()));
        }
        if !seen.insert(target) {
            return Err(OpeningError::Duplicate(target.clone()));
        }
    }
    let mut ordered: Vec<_> = history.acts.iter().collect();
    ordered.sort_by_key(|act| ((act.epoch, act.position), act.id()));
    let mut inputs = Vec::new();
    let mut unavailable_targets = BTreeSet::new();
    let mut dependency_violations = Vec::new();
    for act in ordered {
        let deps = match openings.opening(act) {
            SuppliedOpening::Available(deps) => {
                if deps.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(OpeningError::Dependencies);
                }
                let act_order = (act.epoch, act.position);
                for dependency in deps {
                    let cause = if dependency == act.id() {
                        Some(DependencyCause::SelfDependency)
                    } else {
                        match history.get(dependency) {
                            None => Some(DependencyCause::Missing),
                            Some(target) if (target.epoch, target.position) >= act_order => Some(DependencyCause::NotEarlier),
                            Some(_) => None,
                        }
                    };
                    if let Some(cause) = cause {
                        dependency_violations.push(DependencyViolation {
                            act: act.id().clone(),
                            dependency: dependency.clone(),
                            cause,
                        });
                    }
                }
                Some(deps)
            }
            SuppliedOpening::Unavailable => {
                unavailable_targets.insert(act.id().clone());
                None
            }
        };
        inputs.push(act.structural(deps));
    }
    Ok(ClosureEvidence {
        time_evidence: check_times_structural(&inputs),
        parent_faults: history.parent_faults.clone(),
        dependency_violations,
        unavailable_targets,
    })
}

/// Finite structural fixtures; no authentication authority is represented.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{
        ActCommitments, ActId, ClosureAct, ClosureHeader, ClosureLeg, EdgeId, Layout, PublicReference, Role, StructuralBody,
    };
    use crate::commitments::{ContentCommitment, DependencyCommitment, ProposalCommitment};

    #[derive(Clone, Debug)]
    pub struct FixtureHeader {
        pub id: ActId,
        pub body: StructuralBody,
        pub legs: Vec<crate::CandidateLeg>,
        pub commitments: ActCommitments,
        pub bytes: Vec<u8>,
    }

    impl ClosureHeader for FixtureHeader {
        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
        fn id(&self) -> &ActId {
            &self.id
        }
        fn body(&self) -> &StructuralBody {
            &self.body
        }
        fn legs(&self) -> Vec<ClosureLeg<'_>> {
            self.legs
                .iter()
                .map(|leg| ClosureLeg {
                    id: &leg.id,
                    source: &leg.source,
                    target: &leg.target,
                })
                .collect()
        }
        fn protocol_references(&self) -> &[PublicReference] {
            &[]
        }
        fn commitments(&self) -> &ActCommitments {
            &self.commitments
        }
    }

    #[must_use]
    pub fn registration(sequence: u64, position: u64) -> ClosureAct<FixtureHeader> {
        let id = ActId {
            author: "a".into(),
            sequence,
            family: "Registration".into(),
        };
        let endpoint = |namespace: &str| PublicReference::Named {
            namespace: namespace.into(),
            name: id.author.clone(),
        };
        let header = FixtureHeader {
            id: id.clone(),
            body: StructuralBody {
                settlement: None,
                license: None,
                asserted_parents: Vec::new(),
                layout: Layout::Binary,
                quantities: Vec::new(),
            },
            legs: vec![crate::CandidateLeg {
                id: EdgeId {
                    act: id.clone(),
                    role: Role::Binary,
                },
                source: endpoint("addr"),
                target: endpoint("prof"),
                removal: None,
            }],
            commitments: ActCommitments {
                proposal: ProposalCommitment {
                    recipe: "fixture".into(),
                    bytes: [0; 32],
                },
                content: ContentCommitment {
                    recipe: "fixture".into(),
                    bytes: [0; 32],
                },
                dependency: DependencyCommitment {
                    recipe: "fixture".into(),
                    bytes: [0; 32],
                },
            },
            bytes: vec![1],
        };
        ClosureAct::new(header, vec![2], [0; 64], [0; 64], 1, position, position)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::registration;
    use super::{
        ActId, ClosureAct, ClosureDependencyOpener, ClosureHeader, OpeningError, SuppliedOpening, assess_openings,
        validate_history,
    };
    use crate::{DependencyCause, RecomputedTime};
    use std::collections::BTreeMap;

    #[derive(Debug)]
    struct Openings(BTreeMap<ActId, Vec<ActId>>);

    impl ClosureDependencyOpener<super::test_support::FixtureHeader> for Openings {
        fn targets(&self) -> Vec<&ActId> {
            self.0.keys().collect()
        }
        fn opening<'a>(&'a self, act: &ClosureAct<super::test_support::FixtureHeader>) -> SuppliedOpening<'a> {
            self.0
                .get(act.id())
                .map_or(SuppliedOpening::Unavailable, |ids| SuppliedOpening::Available(ids))
        }
    }

    /// Complete supplied lists change only conditional observations; absence remains unavailable.
    /// ´claim:acts:closure-opening-evidence´
    /// ´test:unit:opening-evidence´
    #[test]
    fn opening_evidence() {
        let first = registration(1, 1);
        let mut second = registration(2, 2);
        second.header.body.asserted_parents.push(first.id().clone());
        let history = validate_history(vec![first.clone(), second], &[]).unwrap();
        let absent = assess_openings(&history, &Openings(BTreeMap::new())).unwrap();
        assert_eq!(absent.unavailable_targets.len(), 2);
        assert!(
            absent
                .time_evidence
                .iter()
                .all(|row| matches!(row.recomputed, RecomputedTime::Unavailable(_)))
        );

        let complete = Openings(BTreeMap::from([
            (first.id().clone(), Vec::new()),
            (history.acts()[1].id().clone(), vec![first.id().clone()]),
        ]));
        let evidence = assess_openings(&history, &complete).unwrap();
        assert_eq!(evidence.unavailable_targets.len(), 0);
        assert_eq!(evidence.dependency_violations.len(), 0);
        assert_eq!(evidence.time_evidence[0].recomputed, RecomputedTime::Available(1));
        assert_eq!(evidence.time_evidence[1].recomputed, RecomputedTime::Available(2));
        assert_eq!(history.acts()[0].header().bytes(), first.header().bytes());
        let violating_list = vec![first.id().clone(), history.acts()[1].id().clone()];
        let violations = assess_openings(
            &history,
            &Openings(BTreeMap::from([(first.id().clone(), violating_list.clone())])),
        )
        .unwrap();
        assert_eq!(violations.dependency_violations.len(), 2);
        assert_eq!(violations.dependency_violations[0].cause, DependencyCause::SelfDependency);
        assert_eq!(violations.dependency_violations[1].cause, DependencyCause::NotEarlier);
        assert_eq!(violating_list, vec![first.id().clone(), history.acts()[1].id().clone()]);
        assert!(matches!(
            assess_openings(
                &history,
                &Openings(BTreeMap::from([(
                    ActId {
                        author: "unknown".into(),
                        sequence: 1,
                        family: "Registration".into(),
                    },
                    Vec::new()
                )]))
            ),
            Err(OpeningError::Unknown(_))
        ));
    }
}
