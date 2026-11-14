//! Private staged writes couple each mutation to its interruption boundary.
//! (´[ROOT-amend:storage:admitted-transaction]´)

use super::{
    DebitVintage, Descriptor, EpochScope, Error, Generation, Identity, Installed, Introduction, Meter, Node, Retained, Selected,
    StorageError, Version, Write, unqualified,
};

pub(super) struct Plan<'a> {
    pub input: &'a Retained,
    pub generation: &'a Generation,
    pub segment: Identity,
    pub descriptor: Option<Descriptor>,
    pub new_scope: bool,
    pub references: Vec<Selected<'a>>,
    pub local: Vec<&'a DebitVintage>,
}

struct Candidate<'a> {
    scope: Option<&'a EpochScope>,
    descriptor: Option<Descriptor>,
    header: bool,
    node: Node<'a>,
}

enum Mutation<'a> {
    Scope(&'a EpochScope),
    Segment(Descriptor),
    Header,
    Chunk(&'a [u8]),
    Observation(&'a Version),
    Reference(Selected<'a>),
    Debit(Introduction<'a>),
    DebitChunk(usize, &'a [u8]),
    Member(usize),
    Publish,
}

impl<'a> Candidate<'a> {
    fn write(&mut self, mutation: Mutation<'a>, point: &mut impl FnMut(Write) -> Result<(), Error>) -> Result<(), Error> {
        let event = match mutation {
            Mutation::Scope(scope) => {
                self.scope = Some(scope);
                Write::Scope
            }
            Mutation::Segment(segment) => {
                self.descriptor = Some(segment);
                Write::Segment
            }
            Mutation::Header => {
                self.header = true;
                Write::Result
            }
            Mutation::Chunk(bytes) => {
                let index = self.node.chunks.len();
                self.node.chunks.push(bytes);
                Write::PackageChunk(index)
            }
            Mutation::Observation(version) => {
                let index = self.node.observations.len();
                self.node.observations.push(version);
                Write::Observation(index)
            }
            Mutation::Reference(reference) => {
                let index = self.node.references.len();
                self.node.references.push(reference);
                Write::Reference(index)
            }
            Mutation::Debit(debit) => {
                let index = self.node.introductions.len();
                self.node.introductions.push(debit);
                Write::Debit(index)
            }
            Mutation::DebitChunk(index, bytes) => {
                let offset = self.node.introductions[index].chunks.len();
                self.node.introductions[index].chunks.push(bytes);
                Write::DebitChunk(index, offset)
            }
            Mutation::Member(index) => {
                self.node.introductions[index].member = true;
                Write::Membership(index)
            }
            Mutation::Publish => Write::Publish,
        };
        point(event)
    }
}

pub(super) fn result<'a>(
    plan: &Plan<'a>,
    meter: &mut Meter,
    point: &mut impl FnMut(Write) -> Result<(), Error>,
) -> Result<Node<'a>, Error> {
    let mut candidate = Candidate {
        scope: None,
        descriptor: None,
        header: false,
        node: Node {
            input: plan.input,
            label: &plan.generation.label,
            generation: plan.generation.ordinal,
            segment: plan.segment,
            chunks: Vec::new(),
            references: Vec::new(),
            reference_index: Vec::new(),
            observations: Vec::new(),
            introductions: Vec::new(),
        },
    };
    let observations = plan
        .input
        .declarations()
        .iter()
        .filter(|u| !unqualified(u.version.family))
        .count();
    meter.reserve(
        &mut candidate.node.chunks,
        plan.input.bytes().len().div_ceil(super::super::MAX_PACKAGE),
    )?;
    meter.reserve(&mut candidate.node.references, plan.references.len())?;
    meter.reserve(&mut candidate.node.reference_index, plan.references.len())?;
    candidate.node.reference_index.extend(0..plan.references.len());
    candidate
        .node
        .reference_index
        .sort_unstable_by(|&a, &b| super::coordinate(plan.references[a].use_).cmp(&super::coordinate(plan.references[b].use_)));
    meter.reserve(&mut candidate.node.observations, observations)?;
    meter.reserve(&mut candidate.node.introductions, plan.local.len())?;
    let mut prepared = Vec::new();
    meter.reserve(&mut prepared, plan.local.len())?;
    for vintage in &plan.local {
        let mut chunks = Vec::new();
        meter.reserve(&mut chunks, vintage.bytes.len().div_ceil(super::super::MAX_PACKAGE))?;
        prepared.push(Introduction {
            origin: *plan.input.event().1,
            vintage,
            chunks,
            member: false,
        });
    }
    if plan.new_scope {
        candidate.write(Mutation::Scope(plan.input.event().0), point)?;
    }
    if let Some(descriptor) = plan.descriptor {
        candidate.write(Mutation::Segment(descriptor), point)?;
    }
    candidate.write(Mutation::Header, point)?;
    for chunk in plan.input.bytes().chunks(super::super::MAX_PACKAGE) {
        candidate.write(Mutation::Chunk(chunk), point)?;
    }
    for use_ in plan.input.declarations().iter().filter(|u| !unqualified(u.version.family)) {
        candidate.write(Mutation::Observation(&use_.version), point)?;
    }
    for &reference in &plan.references {
        candidate.write(Mutation::Reference(reference), point)?;
    }
    for (index, introduction) in prepared.into_iter().enumerate() {
        let bytes = &introduction.vintage.bytes;
        candidate.write(Mutation::Debit(introduction), point)?;
        for chunk in bytes.chunks(super::super::MAX_PACKAGE) {
            candidate.write(Mutation::DebitChunk(index, chunk), point)?;
        }
    }
    for index in 0..plan.local.len() {
        candidate.write(Mutation::Member(index), point)?;
    }
    if !candidate.header
        || candidate.scope.is_some() != plan.new_scope
        || candidate.descriptor != plan.descriptor
        || candidate.node.chunks.len() != plan.input.bytes().len().div_ceil(super::super::MAX_PACKAGE)
        || candidate.node.references != plan.references
        || candidate.node.observations.len() != observations
        || candidate.node.introductions.len() != plan.local.len()
        || candidate
            .node
            .introductions
            .iter()
            .any(|d| !d.member || d.chunks.len() != d.vintage.bytes.len().div_ceil(super::super::MAX_PACKAGE))
    {
        return Err(StorageError::CorruptHistory.into());
    }
    candidate.write(Mutation::Publish, point)?;
    Ok(candidate.node)
}

struct GenerationCandidate<'a> {
    header: bool,
    installed: Installed<'a>,
    versions: Vec<usize>,
    closures: Vec<usize>,
}
impl GenerationCandidate<'_> {
    fn write(&mut self, event: Write, point: &mut impl FnMut(Write) -> Result<(), Error>) -> Result<(), Error> {
        match event {
            Write::Generation => self.header = true,
            Write::Version(index) => self.versions.push(index),
            Write::VersionIntroduction(index) => self.installed.versions.push(index),
            Write::Closure(index) => self.closures.push(index),
            Write::ClosureIntroduction(index) => self.installed.closures.push(index),
            Write::Publish => {}
            _ => return Err(StorageError::CorruptHistory.into()),
        }
        point(event)
    }
}

pub(super) fn generation<'a>(
    input: &'a Generation,
    meter: &mut Meter,
    point: &mut impl FnMut(Write) -> Result<(), Error>,
) -> Result<Installed<'a>, Error> {
    let mut candidate = GenerationCandidate {
        header: false,
        installed: Installed {
            declaration: input,
            versions: Vec::new(),
            closures: Vec::new(),
        },
        versions: Vec::new(),
        closures: Vec::new(),
    };
    meter.reserve(&mut candidate.versions, input.versions.len())?;
    meter.reserve(&mut candidate.closures, input.closures.len())?;
    meter.reserve(&mut candidate.installed.versions, input.versions.len())?;
    meter.reserve(&mut candidate.installed.closures, input.closures.len())?;
    let mut versions = Vec::new();
    let mut closures = Vec::new();
    meter.reserve(&mut versions, input.versions.len())?;
    meter.reserve(&mut closures, input.closures.len())?;
    versions.extend(0..input.versions.len());
    closures.extend(0..input.closures.len());
    versions.sort_unstable_by_key(|&i| {
        let v = &input.versions[i];
        (v.family.name(), v.key.as_str(), v.opens_at)
    });
    closures.sort_unstable_by_key(|&i| {
        let c = &input.closures[i];
        (c.family.name(), c.key.as_str(), c.closes_at)
    });
    candidate.write(Write::Generation, point)?;
    for index in versions {
        candidate.write(Write::Version(index), point)?;
        candidate.write(Write::VersionIntroduction(index), point)?;
    }
    for index in closures {
        candidate.write(Write::Closure(index), point)?;
        candidate.write(Write::ClosureIntroduction(index), point)?;
    }
    if !candidate.header
        || candidate.versions.len() != input.versions.len()
        || candidate.closures.len() != input.closures.len()
        || candidate.versions != candidate.installed.versions
        || candidate.closures != candidate.installed.closures
    {
        return Err(StorageError::CorruptHistory.into());
    }
    // Input indices carry the declared edition order used by exact lookups.
    candidate.installed.versions.sort_unstable();
    candidate.installed.closures.sort_unstable();
    candidate.write(Write::Publish, point)?;
    Ok(candidate.installed)
}
