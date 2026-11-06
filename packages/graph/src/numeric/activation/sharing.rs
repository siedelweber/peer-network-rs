//! Declared evaluation-local constant premises and identical-request evidence reuse.
//! (´[ROOT-rule:design:evaluation-schedule]´)

use super::{Error, Evaluation, Request};
use nrz_cas::{Location, Rational, limits::Budget};
use pn_records::{
    primitive::{Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
};
use std::collections::BTreeMap;

/// One evaluation's checked constants, ordered requests and charged Work ledger.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Debug)]
pub struct Session {
    procedure: Procedure,
    bleed: String,
    constants: [Range; 2],
    premises: Vec<PrimitiveRecord>,
    retained: Vec<Evaluation>,
    budget: Budget,
    active: bool,
    production: bool,
    prepared: Option<super::super::Prepared>,
    index: BTreeMap<Request, usize>,
}

fn limited(procedure: &Procedure, budget: &Budget) -> Result<Procedure, Error> {
    let mut result = procedure.clone();
    let policy = result.enclosure.as_mut().ok_or(Error::Unsupported)?;
    policy.operation.work = policy.operation.work.min(
        procedure
            .maximum_work
            .checked_sub(budget.usage().work)
            .ok_or(Error::Declaration)?,
    );
    Ok(result)
}

fn range(record: &PrimitiveRecord, budget: &mut Budget) -> Result<Range, Error> {
    let interval = record.evidence.bounds.as_ref().ok_or(Error::Declaration)?;
    if record.evidence.attachment.is_none() || record.evidence.resource_fault.is_some() {
        return Err(Error::Declaration);
    }
    Ok(Range {
        lower: interval.lower().exact_string(budget)?,
        upper: interval.upper().exact_string(budget)?,
    })
}

fn beta() -> Query {
    Query {
        coordinates: Vec::new(),
        nodes: vec![Node::Rational("2".into()), Node::Logarithm(0), Node::Multiply(0, 1)],
        target: 2,
        goal: Goal::Width,
    }
}

fn normalization(beta: Range, bleed: &str) -> Query {
    let mut nodes = vec![Node::Coordinate(0), Node::Rational("1".into()), Node::Rational(bleed.into())];
    let target = super::core(&mut nodes, 1, 0, 2, 1);
    Query {
        coordinates: vec![beta],
        nodes,
        target,
        goal: Goal::Width,
    }
}

fn checked(
    procedure: &Procedure,
    query: Query,
    supplied: Option<&PrimitiveRecord>,
    budget: &mut Budget,
    prepared: &mut Option<super::super::Prepared>,
) -> Result<PrimitiveRecord, Error> {
    let policy = limited(procedure, budget)?;
    if supplied
        .is_some_and(|r| r.query != query || r.precision != policy.enclosure.as_ref().map_or(0, |p| p.refinement.precision))
    {
        return Err(Error::Declaration);
    }
    let evidence = if let Some(receiver) = prepared {
        let attachment = supplied
            .map(|r| r.evidence.attachment.as_ref().ok_or(Error::Declaration))
            .transpose()?;
        receiver.run(
            &query,
            attachment,
            policy.enclosure.as_ref().ok_or(Error::Unsupported)?.operation.work,
        )?
    } else if let Some(record) = supplied {
        if record.query != query || record.precision != policy.enclosure.as_ref().ok_or(Error::Unsupported)?.refinement.precision
        {
            return Err(Error::Declaration);
        }
        super::super::replay(
            &policy,
            &query,
            record.evidence.attachment.as_ref().ok_or(Error::Declaration)?,
            None,
        )?
    } else {
        super::super::evaluate(&policy, &query, None)?
    };
    if let Some(fault) = &evidence.resource_fault {
        return Err(Error::Resource(fault.clone()));
    }
    if prepared.is_some()
        && supplied.is_some_and(|r| {
            r.evidence.bounds != evidence.bounds
                || r.evidence.outcome != evidence.outcome
                || r.evidence.resource_fault != evidence.resource_fault
        })
    {
        return Err(Error::Declaration);
    }
    budget.work(evidence.work, Location::new("evaluation-local scalar request"))?;
    Ok(PrimitiveRecord {
        query,
        precision: policy.enclosure.as_ref().ok_or(Error::Unsupported)?.refinement.precision,
        evidence,
    })
}

fn start(procedure: &Procedure, bleed: &str, supplied: Option<&[PrimitiveRecord]>, reuse: bool) -> Result<Session, Error> {
    super::super::preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let mut limits = policy.operation.clone();
    limits.work = procedure.maximum_work;
    let mut budget = Budget::new(limits)?;
    let eta = super::nonnegative(bleed, &mut budget)?;
    if !eta.compare(&Rational::parse("1", &mut budget)?, &mut budget)?.is_lt()
        || supplied.is_some_and(|records| records.len() != 2)
    {
        return Err(Error::Declaration);
    }
    let mut prepared = reuse.then(|| super::super::Prepared::new(procedure));
    let first = checked(
        procedure,
        beta(),
        supplied.and_then(|s| s.first()),
        &mut budget,
        &mut prepared,
    )?;
    let beta = range(&first, &mut budget)?;
    let second = checked(
        procedure,
        normalization(beta.clone(), bleed),
        supplied.and_then(|s| s.get(1)),
        &mut budget,
        &mut prepared,
    )?;
    let q = range(&second, &mut budget)?;
    let lower = Rational::parse(&q.lower, &mut budget)?;
    if lower.is_zero() || lower.is_negative() {
        return Err(Error::Declaration);
    }
    Ok(Session {
        procedure: procedure.clone(),
        bleed: bleed.into(),
        constants: [beta, q],
        premises: vec![first, second],
        retained: Vec::new(),
        budget,
        active: true,
        production: supplied.is_none(),
        prepared,
        index: BTreeMap::new(),
    })
}

fn key_work(input: &Request) -> Result<u64, Error> {
    let mut size = input
        .standing
        .lower
        .len()
        .checked_add(input.standing.upper.len())
        .ok_or(Error::Declaration)?;
    size = size
        .checked_add(input.bleed_squared.len())
        .and_then(|n| n.checked_add(input.wall.as_ref().map_or(0, String::len)))
        .ok_or(Error::Declaration)?;
    if let Some(wall) = &input.wall_enclosure {
        size = size
            .checked_add(wall.lower.len())
            .and_then(|n| n.checked_add(wall.upper.len()))
            .ok_or(Error::Declaration)?;
    }
    if let super::Quantity::Hop { strength, shape } = &input.quantity {
        size = size
            .checked_add(strength.len())
            .and_then(|n| n.checked_add(shape.len()))
            .ok_or(Error::Declaration)?;
    }
    u64::try_from(size.checked_add(1).ok_or(Error::Declaration)?).map_err(|_| Error::Declaration)
}

impl Session {
    /// Release point-result memoization while retaining independently admitted forms and constants.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: Removing cached results cannot admit evidence or widen an operational cap.
    /// # Errors
    /// Refuses a legacy receiver whose evaluation schedule cannot be changed.
    pub fn begin_pass(&mut self) -> Result<(), Error> {
        if self.prepared.is_none() {
            return Err(Error::Declaration);
        }
        self.retained.clear();
        self.index.clear();
        Ok(())
    }

    /// Reduce the prepared receiver's remaining allowance before another map pass.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: This only narrows an operational cap; it admits no evidence or mathematical premise.
    /// # Errors
    /// Refuses legacy receivers and arithmetic overflow; a cap is never increased.
    pub fn cap_remaining(&mut self, remaining: u64) -> Result<(), Error> {
        if self.prepared.is_none() {
            return Err(Error::Declaration);
        }
        self.procedure.maximum_work = self
            .procedure
            .maximum_work
            .min(self.budget.usage().work.checked_add(remaining).ok_or(Error::Declaration)?);
        let spent = self.budget.usage().work;
        let mut limits = self.budget.limits().clone();
        limits.work = self.procedure.maximum_work;
        let mut narrowed = Budget::new(limits)?;
        narrowed.work(spent, Location::new("prepared retained Work prefix"))?;
        self.budget = narrowed;
        Ok(())
    }
    /// Prepare revision-one constants once in an independently owned solve receiver.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// # Errors
    /// Refuses invalid declarations, substituted premises and exhausted setup.
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::activation::sharing::Session::prepared"
        ),
        ret
    )]
    pub fn prepared(procedure: &Procedure, bleed: &str, records: Option<&[PrimitiveRecord]>) -> Result<Self, Error> {
        start(procedure, bleed, records, true)
    }

    /// Descriptor admission Work already included in the cumulative ledger.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: Immutable accounting access cannot supply evidence.
    #[must_use]
    pub fn setup_work(&self) -> u64 {
        self.prepared.as_ref().map_or(0, super::super::Prepared::setup_work)
    }

    /// Start empty and check beta followed by Q(1) at the declaration's precision.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// # Errors
    /// Refuses invalid declarations, domains or constant requests without checked bounds.
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::activation::sharing::Session::new"
        ),
        ret
    )]
    pub fn new(procedure: &Procedure, bleed: &str) -> Result<Self, Error> {
        start(procedure, bleed, None, false)
    }

    /// Rebuild both constant questions in a replay-only receiver using fresh stores.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// # Errors
    /// Refuses substituted constant queries, certificates, domains or declarations.
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::activation::sharing::Session::from_evidence"
        ),
        ret
    )]
    pub fn from_evidence(procedure: &Procedure, bleed: &str, records: &[PrimitiveRecord]) -> Result<Self, Error> {
        start(procedure, bleed, Some(records), false)
    }

    /// Borrow the two producing records in their declared order.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: Immutable access preserves the sealed checked constant premises.
    #[must_use]
    pub fn premises(&self) -> &[PrimitiveRecord] {
        &self.premises
    }

    /// Charged Work, including constant production, lookup and successful requests.
    /// After a refusal this is only the retained prefix, not a completed evaluation total.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: Immutable access reports the evaluation ledger without altering evidence.
    #[must_use]
    pub fn work(&self) -> u64 {
        self.budget.usage().work
    }

    /// Borrow the retained result named by a successful request's local index.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// Justified: Immutable borrowing neither copies evidence nor changes the evaluation ledger.
    #[must_use]
    pub fn evidence(&self, index: usize) -> Option<&Evaluation> {
        self.retained.get(index)
    }

    /// Evaluate in supplied order or borrow identical retained evidence with charged lookup.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// # Errors
    /// Refuses a changed bleed, invalid input, exhausted ledger or declared entry ceiling.
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::activation::sharing::Session::evaluate"
        ),
        ret
    )]
    pub fn evaluate(&mut self, input: &Request) -> Result<usize, Error> {
        if !self.active {
            return Err(Error::Declaration);
        }
        self.active = false;
        if !self.production || input.bleed_squared != self.bleed {
            return Err(Error::Declaration);
        }
        super::wall_binding(&self.procedure, input, &mut self.budget)?;
        self.budget.work(key_work(input)?, Location::new("evaluation memo key"))?;
        if self.prepared.is_some()
            && let Some(index) = self.index.get(input)
        {
            self.active = true;
            return Ok(*index);
        }
        for (index, entry) in self
            .retained
            .iter()
            .enumerate()
            .take(if self.prepared.is_none() { self.retained.len() } else { 0 })
        {
            self.budget
                .work(key_work(&entry.input)?, Location::new("evaluation memo comparison"))?;
            if entry.input == *input {
                self.active = true;
                return Ok(index);
            }
        }
        if u64::try_from(self.retained.len()).map_err(|_| Error::Declaration)?
            >= self
                .procedure
                .enclosure
                .as_ref()
                .ok_or(Error::Unsupported)?
                .operation
                .proof_nodes
        {
            return Err(Error::Declaration);
        }
        let query = super::shared_query(input, &mut self.budget, Some(&self.constants))?;
        let record = checked(&self.procedure, query, None, &mut self.budget, &mut self.prepared)?;
        if record.evidence.attachment.is_none() || record.evidence.resource_fault.is_some() {
            return Err(Error::Declaration);
        }
        if self.prepared.is_some() {
            self.index.insert(input.clone(), self.retained.len());
        }
        self.retained.push(Evaluation {
            input: input.clone(),
            primitive: record,
        });
        self.active = true;
        Ok(self.retained.len() - 1)
    }

    /// Check a dependent request only after this session's constant premises were checked.
    /// (´[ROOT-rule:design:evaluation-schedule]´)
    /// # Errors
    /// Refuses a substituted input, query, precision or attachment and resource exhaustion.
    #[tracing::instrument(
        name = "sig:design:graph",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "sig:design:graph",
            source_item = "numeric::activation::sharing::Session::replay"
        ),
        ret
    )]
    pub fn replay(&mut self, input: &Evaluation) -> Result<PrimitiveRecord, Error> {
        if !self.active {
            return Err(Error::Declaration);
        }
        self.active = false;
        if self.production || input.input.bleed_squared != self.bleed {
            return Err(Error::Declaration);
        }
        super::wall_binding(&self.procedure, &input.input, &mut self.budget)?;
        self.budget
            .work(key_work(&input.input)?, Location::new("evaluation memo key"))?;
        if self.prepared.is_some()
            && let Some(index) = self.index.get(&input.input)
        {
            let entry = &self.retained[*index];
            if entry.primitive.query != input.primitive.query
                || entry.primitive.precision != input.primitive.precision
                || entry.primitive.evidence.attachment != input.primitive.evidence.attachment
                || entry.primitive.evidence.bounds != input.primitive.evidence.bounds
                || entry.primitive.evidence.resource_fault != input.primitive.evidence.resource_fault
                || entry.primitive.evidence.outcome != input.primitive.evidence.outcome
            {
                return Err(Error::Declaration);
            }
            self.active = true;
            return Ok(entry.primitive.clone());
        }
        for entry in self
            .retained
            .iter()
            .take(if self.prepared.is_none() { self.retained.len() } else { 0 })
        {
            self.budget
                .work(key_work(&entry.input)?, Location::new("evaluation memo comparison"))?;
            if entry.input == input.input {
                if entry.primitive.query != input.primitive.query
                    || entry.primitive.precision != input.primitive.precision
                    || entry.primitive.evidence.attachment != input.primitive.evidence.attachment
                {
                    return Err(Error::Declaration);
                }
                self.active = true;
                return Ok(entry.primitive.clone());
            }
        }
        if u64::try_from(self.retained.len()).map_err(|_| Error::Declaration)?
            >= self
                .procedure
                .enclosure
                .as_ref()
                .ok_or(Error::Unsupported)?
                .operation
                .proof_nodes
        {
            return Err(Error::Declaration);
        }
        let query = super::shared_query(&input.input, &mut self.budget, Some(&self.constants))?;
        let record = checked(
            &self.procedure,
            query,
            Some(&input.primitive),
            &mut self.budget,
            &mut self.prepared,
        )?;
        if record.evidence.attachment.is_none() || record.evidence.resource_fault.is_some() {
            return Err(Error::Declaration);
        }
        if self.prepared.is_some() {
            self.index.insert(input.input.clone(), self.retained.len());
        }
        self.retained.push(Evaluation {
            input: input.input.clone(),
            primitive: record.clone(),
        });
        self.active = true;
        Ok(record)
    }
}
