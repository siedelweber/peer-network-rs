//! Edition-one finite DAG inputs; callers supply recorded, shrinkable words.
//! (´def:acts:test-support´)

use crate::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, PublicReference, RemovableProjections, Removal,
    Role, StructuralBody,
};

/// Candidate history and proposals, before any validation under test.
/// (´def:acts:test-support´)
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Complete pre-boundary acts.
    pub history: Vec<CandidateAct>,
    /// Complete post-boundary acts.
    pub proposals: Vec<CandidateAct>,
    /// External names, never isolated history edges.
    pub names: Vec<PublicReference>,
    /// First proposal position.
    pub boundary: crate::Position,
}

/// Generate two history acts and two to ten proposals from shrinkable words.
/// Relations independently select earlier acts; shrinking words preserves validity.
/// Empty input is a valid minimal scenario. Positions and identities are distinct.
/// (´def:acts:test-support´)
#[must_use]
pub fn generate(words: &[u64]) -> Scenario {
    let name = PublicReference::Named {
        namespace: "fixture".into(),
        name: "endpoint".into(),
    };
    let count = 4 + words.len().min(8);
    let mut acts: Vec<CandidateAct> = Vec::new();
    for index in 0..count {
        let word = words.get(index % words.len().max(1)).copied().unwrap_or(0);
        let sequence = u64::try_from(index).unwrap_or(0);
        let id = ActId {
            author: "generated".into(),
            sequence,
            family: "fixture".into(),
        };
        let paired = word & 1 != 0;
        let roles = if paired { vec![Role::A, Role::T] } else { vec![Role::Binary] };
        let parents = acts
            .iter()
            .enumerate()
            .filter(|(i, _)| word & (1 << (i + 1)) != 0)
            .map(|(_, act)| act.id.clone())
            .collect();
        let dependencies: Vec<_> = acts
            .iter()
            .enumerate()
            .filter(|(i, _)| word & (1 << (i + 16)) != 0)
            .map(|(_, act)| act.id.clone())
            .collect();
        acts.push(CandidateAct {
            id: id.clone(),
            body: StructuralBody {
                license: None,
                asserted_parents: parents,
                layout: if paired { Layout::Paired } else { Layout::Binary },
                quantities: Vec::new(),
            },
            legs: roles
                .into_iter()
                .map(|role| CandidateLeg {
                    id: EdgeId { act: id.clone(), role },
                    source: name.clone(),
                    target: name.clone(),
                    removal: None,
                })
                .collect(),
            projections: RemovableProjections {
                content: if word & (1 << 62) == 0 {
                    Removal::Live
                } else {
                    Removal::Tombstoned((u64::from(index >= 2), sequence + 2))
                },
                dependency: if word & (1 << 63) != 0 {
                    DependencyProjection::Tombstoned((u64::from(index >= 2), sequence + 2))
                } else if dependencies.is_empty() {
                    DependencyProjection::FullEmpty
                } else {
                    DependencyProjection::Full(dependencies)
                },
            },
            protocol_references: vec![name.clone()],
            authentication_evidence: vec![1],
            finalization_epoch: u64::from(index >= 2),
            authoritative_position: sequence + 1,
            logical_time: 1,
        });
    }
    let proposals = acts.split_off(2);
    Scenario {
        history: acts,
        proposals,
        names: vec![name],
        boundary: (1, 3),
    }
}

/// Stable mutation names shared by local and outer conformance tiers.
/// The two over-bound lists also contain repeated unresolved identities: their
/// expected refusal establishes count-check precedence, not fault isolation.
/// (´def:acts:test-support´)
pub const CORRUPTIONS: &[&str] = &[
    "duplicate",
    "missing-leg",
    "leg-removal",
    "unresolved-reference",
    "parent-missing",
    "parent-late",
    "parent-duplicate",
    "parent-unsorted",
    "parent-self",
    "parent-bound",
    "dependency-missing",
    "dependency-late",
    "dependency-duplicate",
    "dependency-unsorted",
    "dependency-self",
    "dependency-bound",
    "history-duplicate",
    "edge-only-history",
    "cut-placement",
];

/// Apply one declared mutation and return its exact expected public error.
/// `None` means an unknown mutation or a caller-supplied scenario below the generator's size.
/// Edge-only history and boundary placement are exercised at their respective entry points.
/// (´def:acts:test-support´)
#[must_use]
pub fn corrupt(case: &mut Scenario, mutation: &str) -> Option<crate::ValidationError> {
    use crate::{DependencyCause, InvalidCause, ValidationError};
    if mutation.starts_with("parent-") {
        return corrupt_parent(case, mutation);
    }
    if mutation.starts_with("dependency-") {
        return corrupt_dependency(case, mutation);
    }
    let first = case.proposals.first()?.clone();
    let last = case.proposals.last_mut()?;
    let id = last.id.clone();
    let missing = ActId {
        sequence: 9999,
        ..id.clone()
    };
    let invalid = |cause| ValidationError::InvalidRepresentation { act: id.clone(), cause };
    match mutation {
        "duplicate" => {
            case.proposals.push(first.clone());
            Some(ValidationError::DuplicateAct(first.id))
        }
        "missing-leg" => {
            last.body.layout = Layout::Paired;
            last.legs.truncate(1);
            last.legs.first_mut()?.id.role = Role::A;
            Some(ValidationError::MissingCoLeg { act: id, role: Role::T })
        }
        "leg-removal" => {
            last.legs.first_mut()?.removal = Some(Removal::Live);
            Some(invalid(InvalidCause::CoLegRemoval))
        }
        "unresolved-reference" => {
            let reference = PublicReference::Act(missing);
            last.protocol_references = vec![reference.clone()];
            Some(ValidationError::UnresolvedReference(reference))
        }
        "history-duplicate" => {
            let old = case.history.first()?.clone();
            case.proposals.push(old.clone());
            Some(ValidationError::DuplicateAct(old.id))
        }
        "edge-only-history" => {
            let reference = PublicReference::Edge(case.history.first()?.legs.first()?.id.clone());
            case.names.push(reference.clone());
            Some(ValidationError::InvalidReference(reference))
        }
        "cut-placement" => {
            case.boundary = (first.finalization_epoch, first.authoritative_position + 1);
            Some(ValidationError::Dependency {
                act: first.id,
                dependency: None,
                cause: DependencyCause::BoundaryPlacement,
            })
        }
        _ => None,
    }
}

fn corrupt_parent(case: &mut Scenario, mutation: &str) -> Option<crate::ValidationError> {
    use crate::{ParentCause, ValidationError};
    let first = case.proposals.first()?.clone();
    let last = case.proposals.last_mut()?;
    let id = last.id.clone();
    let missing = ActId {
        sequence: 9999,
        ..id.clone()
    };
    let prior: Vec<_> = case.history.iter().map(|act| act.id.clone()).collect();
    let parent = |parent, cause| ValidationError::Parent {
        act: id.clone(),
        parent,
        cause,
    };
    match mutation {
        "parent-missing" => {
            last.body.asserted_parents = vec![missing.clone()];
            Some(parent(Some(missing), ParentCause::Missing))
        }
        "parent-late" => {
            last.authoritative_position = first.authoritative_position;
            last.projections.dependency = DependencyProjection::FullEmpty;
            last.body.asserted_parents = vec![first.id.clone()];
            Some(parent(Some(first.id), ParentCause::NotEarlier))
        }
        "parent-duplicate" => {
            last.body.asserted_parents = vec![prior.first()?.clone(); 2];
            Some(parent(None, ParentCause::NonCanonical))
        }
        "parent-unsorted" => {
            last.body.asserted_parents = prior.into_iter().rev().collect();
            Some(parent(None, ParentCause::NonCanonical))
        }
        "parent-self" => {
            last.body.asserted_parents = vec![id.clone()];
            Some(parent(Some(id.clone()), ParentCause::SelfParent))
        }
        "parent-bound" => {
            last.body.asserted_parents = vec![missing; crate::MAX_ASSERTED_PARENTS + 1];
            Some(parent(None, ParentCause::TooMany))
        }
        _ => None,
    }
}

fn corrupt_dependency(case: &mut Scenario, mutation: &str) -> Option<crate::ValidationError> {
    use crate::{DependencyCause, ValidationError};
    let first = case.proposals.first()?.clone();
    let last = case.proposals.last_mut()?;
    let id = last.id.clone();
    let missing = ActId {
        sequence: 9999,
        ..id.clone()
    };
    let prior: Vec<_> = case.history.iter().map(|act| act.id.clone()).collect();
    let dependency = |dependency, cause| ValidationError::Dependency {
        act: id.clone(),
        dependency,
        cause,
    };
    match mutation {
        "dependency-missing" => {
            last.projections.dependency = DependencyProjection::Full(vec![missing.clone()]);
            Some(dependency(Some(missing), DependencyCause::Missing))
        }
        "dependency-late" => {
            last.authoritative_position = first.authoritative_position;
            last.body.asserted_parents.clear();
            last.projections.dependency = DependencyProjection::Full(vec![first.id.clone()]);
            Some(dependency(Some(first.id), DependencyCause::NotEarlier))
        }
        "dependency-duplicate" => {
            last.projections.dependency = DependencyProjection::Full(vec![prior.first()?.clone(); 2]);
            Some(dependency(None, DependencyCause::NonCanonical))
        }
        "dependency-unsorted" => {
            last.projections.dependency = DependencyProjection::Full(prior.into_iter().rev().collect());
            Some(dependency(None, DependencyCause::NonCanonical))
        }
        "dependency-self" => {
            last.projections.dependency = DependencyProjection::Full(vec![id.clone()]);
            Some(dependency(Some(id.clone()), DependencyCause::SelfDependency))
        }
        "dependency-bound" => {
            last.projections.dependency = DependencyProjection::Full(vec![missing; crate::MAX_DEPENDENCIES + 1]);
            Some(dependency(None, DependencyCause::TooMany))
        }
        _ => None,
    }
}

/// Shared bounded numeric inputs, with expectations owned separately by each consumer.
/// (´def:numerics:shared-inputs´)
#[derive(Clone, Copy, Debug)]
pub struct NumericInput {
    /// Nonnegative burn amount below sixty-four.
    pub burn: u64,
    /// Positive numeraire amount at most thirty-one.
    pub numeraire: u64,
    /// Positive market or recoinage factor at most seven.
    pub factor: u64,
    /// Nonnegative action count below sixteen.
    pub actions: u64,
}

/// Map shrinking word vectors to finite exact cases, without providing an oracle.
/// (´def:numerics:shared-inputs´)
#[must_use]
pub fn numeric_input(words: &[u64]) -> NumericInput {
    NumericInput {
        burn: words.first().copied().unwrap_or(0) % 64,
        numeraire: words.get(1).copied().unwrap_or(0) % 31 + 1,
        factor: words.get(2).copied().unwrap_or(0) % 7 + 1,
        actions: words.get(3).copied().unwrap_or(0) % 16,
    }
}

/// Versioned numeric roster; each input exercises coordinates, charges and exact refusals.
/// (´def:numerics:shared-inputs´)
pub const NUMERIC_CASES: [(&str, [u64; 4]); 6] = [
    ("zero-amount", [0, 0, 0, 0]),
    ("coexpressed-units", [12, 1, 3, 5]),
    ("market-repricing", [24, 2, 5, 7]),
    ("fractional-reduction", [1, 30, 6, 15]),
    ("charged-vintage", [63, 29, 4, 13]),
    ("subunit-cost", [7, 4, 2, 3]),
];
/// Shared burn candidates and controlled corruptions; public proof fixtures are not chain evidence.
/// (´def:burn:test-support´)
pub mod burn;
