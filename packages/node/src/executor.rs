//! Bounded in-process byte entry for the unserved control edition.
//! (´[ROOT-amend:api:node-package]´) (´[ROOT-amend:api:control-message-errors]´)

use async_graphql::{
    Context, EmptySubscription, Object, Request, Response, Schema, ServerError, SimpleObject, Value as GraphValue,
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextExecute},
};
use async_graphql_parser::{
    parse_query,
    types::{DocumentOperations, ExecutableDocument, OperationType, Selection, SelectionSet},
};
use pn_interchange::{
    DecodeError, EncodingError, EncodingUsage, ResponseView, ResponseWriteError, Text, TransportLimits, TransportMessage,
    TransportUsage, Value, write_transport_response,
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
const EDITION: &str =
    "schema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0";

/// A refusal for which no response message exists.
/// (´[ROOT-amend:api:control-message-errors]´)
/// After dispatch, a response-limit or typed presentation refusal means the result was not presented;
/// the start outcome is unknown, and neither readiness nor rollback can be inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// The build-owned register still has a pending required value.
    LimitsUnadmitted,
    /// The build-owned schema and register cannot be agreed or selected.
    Configuration,
    /// A new decoder refusal has no decided message class.
    DecoderContract,
    /// Neither the original response nor its one replacement could be written.
    ResponseLimit(EncodingError),
    /// Response presentation repeated one name.
    DuplicateResponseName,
    /// Response presentation supplied a value outside its vocabulary.
    ResponseValueUnsupported,
}

#[derive(Clone, Debug)]
struct Limits {
    #[cfg(test)]
    schema_source: usize,
    #[cfg(test)]
    register_source: usize,
    graphql_source: usize,
    transport: usize,
    decoded_bytes: usize,
    decoded_items: usize,
    cbor_nesting: usize,
    input_nesting: usize,
    decoding_work: usize,
    lexical_tokens: usize,
    source_nesting: usize,
    selection_depth: usize,
    root_selections: usize,
    fields: usize,
    aliases: usize,
    fragment_work: usize,
    resolver_work: usize,
    response: usize,
    concurrency: usize,
    execution: usize,
    #[cfg(test)]
    cancellation_drain: usize,
    #[cfg(test)]
    shell_start: usize,
    #[cfg(test)]
    shell_stop: usize,
    start_weight: usize,
}

impl Limits {
    #[cfg(test)]
    fn positive(&self) -> bool {
        [
            self.schema_source,
            self.register_source,
            self.graphql_source,
            self.transport,
            self.decoded_bytes,
            self.decoded_items,
            self.cbor_nesting,
            self.input_nesting,
            self.decoding_work,
            self.lexical_tokens,
            self.source_nesting,
            self.selection_depth,
            self.root_selections,
            self.fields,
            self.aliases,
            self.fragment_work,
            self.resolver_work,
            self.response,
            self.concurrency,
            self.execution,
            self.cancellation_drain,
            self.shell_start,
            self.shell_stop,
            self.start_weight,
        ]
        .into_iter()
        .all(|value| value > 0)
    }

    fn transport_limits(&self) -> TransportLimits {
        TransportLimits {
            input_bytes: self.transport,
            allocation_bytes: self.decoded_bytes,
            items: self.decoded_items,
            depth: self.input_nesting,
            nesting: self.cbor_nesting,
            work: self.decoding_work,
        }
    }
}

#[derive(Clone, Debug)]
struct StartInputs {
    edition_supported: bool,
    bootstrap_valid: bool,
    cancelled: bool,
    failures: StartFailures,
    count: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
struct StartFailures {
    resource_exhausted: bool,
    start_failed: bool,
}

#[derive(Clone)]
struct StartRun {
    inputs: StartInputs,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    edition: String,
}

/// An admitted execution context. The build-owned draft cannot construct a served context while any value is pending.
/// (´[ROOT-amend:api:test-schema-plan]´)
#[derive(Debug)]
pub struct ExecutionContext {
    limits: Limits,
    start: StartInputs,
    cancelled: Arc<AtomicBool>,
    active: AtomicUsize,
    edition: String,
}

impl ExecutionContext {
    /// Validate the build-owned schema and register before constructing a served context.
    /// (´[ROOT-amend:api:test-schema-plan]´)
    ///
    /// # Errors
    /// Returns `LimitsUnadmitted` while a required register value is pending, or `Configuration` for a disagreement.
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "NODE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "executor::ExecutionContext::served"
        ),
        ret
    )]
    pub fn served() -> Result<Self, EntryError> {
        #[cfg(test)]
        match crate::admission::embedded_pending() {
            Ok(true) => Err(EntryError::LimitsUnadmitted),
            Ok(false) | Err(()) => Err(EntryError::Configuration),
        }
        #[cfg(not(test))]
        {
            Err(EntryError::LimitsUnadmitted)
        }
    }

    #[cfg(test)]
    fn unserved(limits: Limits, start: StartInputs) -> Result<Self, EntryError> {
        if !limits.positive()
            || limits.schema_source < include_str!("../../interchange/schema/control.graphql").len()
            || limits.register_source < include_str!("../schema/control-register-draft.toml").len()
        {
            return Err(EntryError::Configuration);
        }
        Ok(Self {
            limits,
            start,
            cancelled: Arc::new(AtomicBool::new(false)),
            active: AtomicUsize::new(0),
            edition: EDITION.to_owned(),
        })
    }

    #[cfg(test)]
    fn checked_unserved(draft: &str, limits: Limits, start: StartInputs) -> Result<Self, EntryError> {
        match crate::admission::synthetic_pending(draft) {
            Ok(true) => Err(EntryError::LimitsUnadmitted),
            Ok(false) => Self::unserved(limits, start),
            Err(()) => Err(EntryError::Configuration),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Malformed,
    Invalid,
    Unsupported,
    ResourceLimit,
    Cancelled,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::Invalid => "Invalid",
            Self::Unsupported => "Unsupported",
            Self::ResourceLimit => "ResourceLimit",
            Self::Cancelled => "Cancelled",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Malformed => "Request syntax is malformed.",
            Self::Invalid => "Request validation failed.",
            Self::Unsupported => "Request exceeds the supported operation or limits.",
            Self::ResourceLimit => "Response cannot be completed within the declared limits.",
            Self::Cancelled => "Request was cancelled before dispatch.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refusal {
    class: Class,
    ceiling: Option<&'static str>,
}

impl Refusal {
    const fn new(class: Class, ceiling: Option<&'static str>) -> Self {
        Self { class, ceiling }
    }
    const fn malformed() -> Self {
        Self::new(Class::Malformed, None)
    }
    const fn invalid() -> Self {
        Self::new(Class::Invalid, None)
    }
    const fn unsupported(ceiling: Option<&'static str>) -> Self {
        Self::new(Class::Unsupported, ceiling)
    }
    const fn limit(ceiling: Option<&'static str>) -> Self {
        Self::new(Class::ResourceLimit, ceiling)
    }
}

struct Permit<'a>(&'a AtomicUsize);

impl Drop for Permit<'_> {
    #[doc = "Justified: Permit release inherits the enclosing byte execution span; another span would duplicate the same concurrency outcome."]
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn admit_concurrency(context: &ExecutionContext) -> Result<Permit<'_>, Refusal> {
    let mut current = context.active.load(Ordering::Acquire);
    loop {
        if current >= context.limits.concurrency {
            return Err(Refusal::unsupported(Some("concurrency")));
        }
        match context
            .active
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(Permit(&context.active)),
            Err(observed) => current = observed,
        }
    }
}

fn boundary(context: &ExecutionContext, deadline: Instant) -> Result<(), Refusal> {
    if context.cancelled.load(Ordering::Acquire) {
        Err(Refusal::new(Class::Cancelled, None))
    } else if Instant::now() >= deadline {
        Err(Refusal::limit(Some("execution")))
    } else {
        Ok(())
    }
}

fn decode_refusal(error: &DecodeError) -> Result<Refusal, EntryError> {
    let result = match error {
        DecodeError::Truncated { .. }
        | DecodeError::TrailingBytes { .. }
        | DecodeError::IllFormed { .. }
        | DecodeError::InvalidUtf8 { .. }
        | DecodeError::TransportValue { .. }
        | DecodeError::DuplicateMapKey { .. } => Refusal::malformed(),
        DecodeError::TransportLimit { resource, .. } => {
            let key = match *resource {
                "input bytes" => "transport",
                "allocation bytes" => "decoded_bytes",
                "items" => "decoded_items",
                "depth" => "input_nesting",
                "nesting" => "cbor_nesting",
                "work" => "decoding_work",
                _ => return Err(EntryError::DecoderContract),
            };
            Refusal::unsupported(Some(key))
        }
        DecodeError::TransportAllocation { .. } => Refusal::limit(None),
        _ => return Err(EntryError::DecoderContract),
    };
    Ok(result)
}

struct Message<'a> {
    query: &'a str,
    operation_name: Option<&'a str>,
}

fn graphql_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn message(value: &Value) -> Result<Message<'_>, Refusal> {
    let Value::Map(map) = value else {
        return Err(Refusal::invalid());
    };
    let mut query = None;
    let mut operation_name = None;
    for (key, item) in map.iter() {
        let Value::Text(name) = key else {
            return Err(Refusal::invalid());
        };
        match name.as_str() {
            "query" => {
                let Value::Text(text) = item else {
                    return Err(Refusal::invalid());
                };
                query = Some(text.as_str());
            }
            "operationName" => {
                let Value::Text(text) = item else {
                    return Err(Refusal::invalid());
                };
                if !graphql_name(text.as_str()) {
                    return Err(Refusal::invalid());
                }
                operation_name = Some(text.as_str());
            }
            "variables" => {
                let Value::Map(variables) = item else {
                    return Err(Refusal::invalid());
                };
                if variables
                    .iter()
                    .any(|(key, _)| !matches!(key, Value::Text(text) if graphql_name(text.as_str())))
                {
                    return Err(Refusal::invalid());
                }
            }
            _ => return Err(Refusal::invalid()),
        }
    }
    Ok(Message {
        query: query.ok_or(Refusal::invalid())?,
        operation_name,
    })
}

fn number_token(bytes: &[u8], mut i: usize) -> Result<usize, Refusal> {
    if bytes[i] == b'-' {
        i += 1;
    }
    match bytes.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        _ => return Err(Refusal::malformed()),
    }
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        if !bytes.get(i).is_some_and(u8::is_ascii_digit) {
            return Err(Refusal::malformed());
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !bytes.get(i).is_some_and(u8::is_ascii_digit) {
            return Err(Refusal::malformed());
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    Ok(i)
}

fn string_token(bytes: &[u8], mut i: usize) -> Result<usize, Refusal> {
    if bytes.get(i..i + 3) == Some(b"\"\"\"") {
        i += 3;
        while i + 2 < bytes.len() {
            if bytes.get(i..i + 4) == Some(b"\\\"\"\"") {
                i += 4;
                continue;
            }
            if bytes[i..i + 3] == *b"\"\"\"" {
                break;
            }
            i += 1;
        }
        if i + 2 >= bytes.len() {
            return Err(Refusal::malformed());
        }
        return Ok(i + 3);
    }
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if matches!(bytes.get(i + 1), Some(b'\r' | b'\n')) {
                return Err(Refusal::malformed());
            }
            i = i.saturating_add(2);
        } else if bytes[i] == b'"' {
            return Ok(i + 1);
        } else if matches!(bytes[i], b'\r' | b'\n') {
            return Err(Refusal::malformed());
        } else {
            i += 1;
        }
    }
    Err(Refusal::malformed())
}

fn lexical(source: &str, limits: &Limits) -> Result<(), Refusal> {
    if source.len() > limits.graphql_source {
        return Err(Refusal::unsupported(Some("graphql_source")));
    }
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut tokens = 0usize;
    let mut open = Vec::new();
    while i < bytes.len() {
        let start = i;
        let byte = bytes[i];
        if matches!(byte, b'\t' | b' ' | b'\r' | b'\n' | b',') {
            i += 1;
            continue;
        }
        if bytes.get(i..i + 3) == Some(&[0xef, 0xbb, 0xbf]) {
            i += 3;
            continue;
        }
        if byte == b'#' {
            while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
                i += 1;
            }
            continue;
        }
        if matches!(byte, b')' | b']' | b'}') {
            let expected = match byte {
                b')' => b'(',
                b']' => b'[',
                _ => b'{',
            };
            if open.pop() != Some(expected) {
                return Err(Refusal::malformed());
            }
            i += 1;
        } else if byte == b'"' {
            i = string_token(bytes, i)?;
        } else if byte.is_ascii_alphabetic() || byte == b'_' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
        } else if byte.is_ascii_digit() || byte == b'-' {
            i = number_token(bytes, i)?;
        } else if byte == b'.' && bytes.get(i..i + 3) == Some(b"...") {
            i += 3;
        } else if matches!(byte, b'!' | b'$' | b'&' | b'(' | b':' | b'=' | b'@' | b'[' | b'{' | b'|') {
            i += 1;
        } else {
            return Err(Refusal::malformed());
        }
        tokens = tokens.checked_add(1).ok_or(Refusal::unsupported(Some("lexical_tokens")))?;
        if tokens > limits.lexical_tokens {
            return Err(Refusal::unsupported(Some("lexical_tokens")));
        }
        if matches!(byte, b'(' | b'[' | b'{') {
            if open.len() >= limits.source_nesting {
                return Err(Refusal::unsupported(Some("source_nesting")));
            }
            open.try_reserve(1).map_err(|_| Refusal::limit(None))?;
            open.push(byte);
        }
        debug_assert!(i > start);
    }
    if !open.is_empty() {
        return Err(Refusal::malformed());
    }
    Ok(())
}

fn selected_operation<'a>(
    document: &'a ExecutableDocument,
    name: Option<&str>,
) -> Result<&'a async_graphql_parser::types::OperationDefinition, Refusal> {
    match (&document.operations, name) {
        (DocumentOperations::Single(operation), None) => Ok(&operation.node),
        (DocumentOperations::Multiple(operations), Some(name)) => operations
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, operation)| &operation.node)
            .ok_or(Refusal::invalid()),
        (DocumentOperations::Multiple(operations), None) if operations.len() == 1 => operations
            .values()
            .next()
            .map(|operation| &operation.node)
            .ok_or(Refusal::invalid()),
        _ => Err(Refusal::invalid()),
    }
}

fn fragment_set<'a>(document: &'a ExecutableDocument, name: &str) -> Result<&'a SelectionSet, Refusal> {
    document
        .fragments
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .map(|(_, fragment)| &fragment.node.selection_set.node)
        .ok_or(Refusal::invalid())
}

struct GraphFrame<'a> {
    name: Option<&'a str>,
    set: &'a SelectionSet,
    next: usize,
}

fn check_fragment_graph(document: &ExecutableDocument, root: &SelectionSet, tokens: usize) -> Result<(), Refusal> {
    let mut stack = Vec::new();
    stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
    stack.push(GraphFrame {
        name: None,
        set: root,
        next: 0,
    });
    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    while let Some(frame) = stack.last_mut() {
        if frame.next == frame.set.items.len() {
            if let Some(name) = frame.name {
                active.remove(name);
                complete.insert(name);
            }
            stack.pop();
            continue;
        }
        let selection = &frame.set.items[frame.next].node;
        frame.next += 1;
        let (name, set) = match selection {
            Selection::FragmentSpread(spread) => {
                let name = spread.node.fragment_name.node.as_str();
                (Some(name), fragment_set(document, name)?)
            }
            Selection::InlineFragment(fragment) => (None, &fragment.node.selection_set.node),
            Selection::Field(field) => (None, &field.node.selection_set.node),
        };
        if let Some(name) = name {
            if active.contains(name) {
                return Err(Refusal::invalid());
            }
            if complete.contains(name) {
                continue;
            }
            active.insert(name);
        }
        if stack.len() >= tokens {
            return Err(Refusal::invalid());
        }
        stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
        stack.push(GraphFrame { name, set, next: 0 });
    }
    Ok(())
}

struct ExpandFrame<'a> {
    set: &'a SelectionSet,
    next: usize,
    depth: usize,
}

struct Expansion<'a> {
    root_response_name: &'a str,
    nested_names: Vec<&'a str>,
    cost: Option<usize>,
}

fn count_expansion<'a>(
    document: &'a ExecutableDocument,
    operation: &'a async_graphql_parser::types::OperationDefinition,
    limits: &Limits,
) -> Result<Expansion<'a>, Refusal> {
    let mut stack = Vec::new();
    stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
    stack.push(ExpandFrame {
        set: &operation.selection_set.node,
        next: 0,
        depth: 0,
    });
    let mut fields = 0usize;
    let mut roots = 0usize;
    let mut aliases = 0usize;
    let mut fragments = 0usize;
    let mut unsupported_field = false;
    let mut root_response_name = None;
    let mut nested_names = Vec::new();
    while let Some(frame) = stack.last_mut() {
        if frame.next == frame.set.items.len() {
            stack.pop();
            continue;
        }
        let selection = &frame.set.items[frame.next].node;
        frame.next += 1;
        let depth = frame.depth;
        match selection {
            Selection::FragmentSpread(spread) => {
                fragments = fragments.checked_add(1).ok_or(Refusal::unsupported(Some("fragment_work")))?;
                if fragments > limits.fragment_work {
                    return Err(Refusal::unsupported(Some("fragment_work")));
                }
                let set = fragment_set(document, spread.node.fragment_name.node.as_str())?;
                stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
                stack.push(ExpandFrame { set, next: 0, depth });
            }
            Selection::InlineFragment(fragment) => {
                stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
                stack.push(ExpandFrame {
                    set: &fragment.node.selection_set.node,
                    next: 0,
                    depth,
                });
            }
            Selection::Field(field) => {
                let next_depth = depth.checked_add(1).ok_or(Refusal::unsupported(Some("selection_depth")))?;
                if next_depth > limits.selection_depth {
                    return Err(Refusal::unsupported(Some("selection_depth")));
                }
                fields = fields.checked_add(1).ok_or(Refusal::unsupported(Some("fields")))?;
                if fields > limits.fields {
                    return Err(Refusal::unsupported(Some("fields")));
                }
                if field.node.alias.is_some() {
                    aliases = aliases.checked_add(1).ok_or(Refusal::unsupported(Some("aliases")))?;
                    if aliases > limits.aliases {
                        return Err(Refusal::unsupported(Some("aliases")));
                    }
                }
                let name = field.node.name.node.as_str();
                if matches!(name, "__schema" | "__type" | "__typename") {
                    unsupported_field = true;
                }
                let response_name = field.node.response_key().node.as_str();
                if next_depth == 1 {
                    if matches!(name, "inspect" | "administer") {
                        unsupported_field = true;
                    }
                    roots = roots.checked_add(1).ok_or(Refusal::unsupported(Some("root_selections")))?;
                    if roots > limits.root_selections {
                        return Err(Refusal::unsupported(Some("root_selections")));
                    }
                    root_response_name.get_or_insert(response_name);
                } else if next_depth == 2 && !nested_names.contains(&response_name) {
                    nested_names.try_reserve(1).map_err(|_| Refusal::limit(None))?;
                    nested_names.push(response_name);
                }
                if !field.node.selection_set.node.items.is_empty() {
                    stack.try_reserve(1).map_err(|_| Refusal::limit(None))?;
                    stack.push(ExpandFrame {
                        set: &field.node.selection_set.node,
                        next: 0,
                        depth: next_depth,
                    });
                }
            }
        }
    }
    if matches!(operation.ty, OperationType::Query | OperationType::Subscription) || unsupported_field {
        return Err(Refusal::unsupported(None));
    }
    if roots != 1 {
        return Err(Refusal::invalid());
    }
    let cost = limits.start_weight.checked_mul(roots);
    Ok(Expansion {
        root_response_name: root_response_name.ok_or(Refusal::invalid())?,
        nested_names,
        cost,
    })
}

#[derive(Clone)]
struct CostGate {
    cost: Option<usize>,
    limit: usize,
    exceeded: Arc<AtomicBool>,
}

impl ExtensionFactory for CostGate {
    #[doc = "Justified: GraphQL extension construction inherits the enclosing byte execution span and has no independent input or outcome."]
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(self.clone())
    }
}

#[async_graphql::async_trait::async_trait]
impl Extension for CostGate {
    #[doc = "Justified: Resolver cost checking inherits the enclosing byte execution span and reports its refusal through that result."]
    async fn execute(&self, context: &ExtensionContext<'_>, operation_name: Option<&str>, next: NextExecute<'_>) -> Response {
        if self.cost.is_none_or(|cost| cost > self.limit) {
            self.exceeded.store(true, Ordering::Release);
            Response::from_errors(vec![ServerError::new("bounded resolver work refused", None)])
        } else {
            next.run(context, operation_name).await
        }
    }
}

struct ControlQuery;

#[Object(name = "ControlQuery")]
impl ControlQuery {
    async fn unavailable(&self) -> Option<bool> {
        None
    }
}

struct ControlMutation;

#[derive(Clone, SimpleObject)]
#[graphql(name = "ControlStartResult")]
struct ControlStartResult {
    ready: bool,
    edition: String,
    failure: Option<String>,
}

#[Object(name = "ControlMutation")]
impl ControlMutation {
    async fn start(&self, context: &Context<'_>) -> ControlStartResult {
        let run = context.data_unchecked::<StartRun>();
        run.inputs.count.fetch_add(1, Ordering::AcqRel);
        let failure = if !run.inputs.edition_supported {
            Some("EditionUnsupported")
        } else if !run.inputs.bootstrap_valid {
            Some("BootstrapInvalid")
        } else if run.inputs.cancelled || run.cancelled.load(Ordering::Acquire) {
            Some("Cancelled")
        } else if Instant::now() >= run.deadline || run.inputs.failures.resource_exhausted {
            Some("ResourceLimit")
        } else if run.inputs.failures.start_failed {
            Some("StartFailed")
        } else {
            None
        };
        ControlStartResult {
            ready: failure.is_none(),
            edition: run.edition.clone(),
            failure: failure.map(str::to_owned),
        }
    }
}

struct PresentationBudget {
    ceiling: usize,
    used: usize,
}

impl PresentationBudget {
    fn new(ceiling: usize) -> Self {
        Self { ceiling, used: 0 }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), EntryError> {
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or(EntryError::ResponseLimit(EncodingError::Length))?;
        if self.used > self.ceiling {
            return Err(EntryError::ResponseLimit(EncodingError::Limit));
        }
        Ok(())
    }

    fn text(&mut self, source: &str) -> Result<Value, EntryError> {
        self.charge(source.len())?;
        let mut text = String::new();
        text.try_reserve_exact(source.len())
            .map_err(|_| EntryError::ResponseLimit(EncodingError::Allocation))?;
        text.push_str(source);
        if text.capacity() != source.len() {
            return Err(EntryError::ResponseLimit(EncodingError::Allocation));
        }
        Ok(Value::Text(Text::from(text)))
    }

    fn reserve_vec<T>(&mut self, vector: &mut Vec<T>, extra: usize) -> Result<(), EntryError> {
        self.charge(
            extra
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(EntryError::ResponseLimit(EncodingError::Length))?,
        )?;
        vector
            .try_reserve_exact(extra)
            .map_err(|_| EntryError::ResponseLimit(EncodingError::Allocation))
    }

    fn writer_ceiling(&self) -> Result<usize, EntryError> {
        self.ceiling
            .checked_sub(self.used)
            .filter(|remaining| *remaining > 0)
            .ok_or(EntryError::ResponseLimit(EncodingError::Limit))
    }
}

fn writer(fields: &[(&str, ResponseView<'_>)], budget: &PresentationBudget) -> Result<TransportMessage, EntryError> {
    let mut usage = EncodingUsage::default();
    write_transport_response(fields, budget.writer_ceiling()?, &mut usage, |_| Ok(())).map_err(|error| match error {
        ResponseWriteError::ResponseLimit(cause) => EntryError::ResponseLimit(cause),
        ResponseWriteError::DuplicateResponseName => EntryError::DuplicateResponseName,
        ResponseWriteError::ResponseValueUnsupported => EntryError::ResponseValueUnsupported,
    })
}

fn present_error(context: &ExecutionContext, refusal: Refusal) -> Result<TransportMessage, EntryError> {
    let mut budget = PresentationBudget::new(context.limits.response);
    let message = budget.text(refusal.class.message())?;
    let class = budget.text(refusal.class.name())?;
    let edition = budget.text(&context.edition)?;
    let ceiling = match refusal.ceiling {
        Some(key) => budget.text(key)?,
        None => Value::Null,
    };
    let extensions = [
        ("class", ResponseView::Value(&class)),
        ("edition", ResponseView::Value(&edition)),
        ("ceiling", ResponseView::Value(&ceiling)),
    ];
    let error = [
        ("message", ResponseView::Value(&message)),
        ("extensions", ResponseView::Object(&extensions)),
    ];
    let errors = [ResponseView::Object(&error)];
    let root = [("errors", ResponseView::Array(&errors))];
    writer(&root, &budget)
}

fn graph_scalar(value: &GraphValue, budget: &mut PresentationBudget) -> Result<Value, EntryError> {
    match value {
        GraphValue::Boolean(boolean) => Ok(Value::Bool(*boolean)),
        GraphValue::String(text) => budget.text(text),
        GraphValue::Null => Ok(Value::Null),
        _ => Err(EntryError::ResponseValueUnsupported),
    }
}

fn present_result(
    context: &ExecutionContext,
    response: &Response,
    expansion: &Expansion<'_>,
) -> Result<TransportMessage, EntryError> {
    let GraphValue::Object(root) = &response.data else {
        return Err(EntryError::ResponseValueUnsupported);
    };
    let (_, GraphValue::Object(start)) = root
        .iter()
        .find(|(name, _)| name.as_str() == expansion.root_response_name)
        .ok_or(EntryError::ResponseValueUnsupported)?
    else {
        return Err(EntryError::ResponseValueUnsupported);
    };
    let mut budget = PresentationBudget::new(context.limits.response);
    let mut values = Vec::new();
    let mut names = Vec::new();
    for name in &expansion.nested_names {
        if let Some((_, value)) = start.iter().find(|(key, _)| key.as_str() == *name) {
            budget.reserve_vec(&mut values, 1)?;
            values.push(graph_scalar(value, &mut budget)?);
            budget.reserve_vec(&mut names, 1)?;
            names.push(*name);
        }
    }
    let mut fields = Vec::new();
    budget.reserve_vec(&mut fields, names.len())?;
    for (name, value) in names.iter().zip(&values) {
        fields.push((*name, ResponseView::Value(value)));
    }
    let data = [(expansion.root_response_name, ResponseView::Object(&fields))];
    let message = [("data", ResponseView::Object(&data))];
    writer(&message, &budget)
}

fn present_with_replacement(
    context: &ExecutionContext,
    original: impl FnOnce() -> Result<TransportMessage, EntryError>,
) -> Result<TransportMessage, EntryError> {
    match original() {
        Ok(message) => Ok(message),
        Err(EntryError::ResponseLimit(cause)) => {
            let ceiling = match cause {
                EncodingError::Length | EncodingError::Limit => Some("response"),
                EncodingError::Allocation => None,
                EncodingError::Reservation => return Err(EntryError::ResponseLimit(cause)),
            };
            present_error(context, Refusal::limit(ceiling))
        }
        Err(error) => Err(error),
    }
}

fn refuse(context: &ExecutionContext, refusal: Refusal) -> Result<TransportMessage, EntryError> {
    present_with_replacement(context, || present_error(context, refusal))
}

/// Execute one bounded CBOR GraphQL control message in process.
/// A served context cannot currently be constructed from the pending build-owned register.
/// (´[ROOT-amend:api:node-package]´) (´[ROOT-amend:api:control-message-errors]´)
/// A `ResourceLimit` with `response` or no ceiling after dispatch, or any typed refusal,
/// means only that the result was not presented. Its start outcome is unknown, never readiness.
///
/// # Errors
/// Returns a typed no-message refusal when construction, decoder contracts, or both bounded response attempts prevent a message.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "NODE",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "executor::execute"
    ),
    ret
)]
pub async fn execute(bytes: &[u8], context: &ExecutionContext) -> Result<TransportMessage, EntryError> {
    let nanoseconds = u64::try_from(context.limits.execution).map_err(|_| EntryError::Configuration)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_nanos(nanoseconds))
        .ok_or(EntryError::Configuration)?;
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    let _permit = match admit_concurrency(context) {
        Ok(permit) => permit,
        Err(refusal) => return refuse(context, refusal),
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }

    let mut usage = TransportUsage::default();
    let value = match Value::from_transport_bytes(bytes, context.limits.transport_limits(), &mut usage) {
        Ok(value) => value,
        Err(error) => {
            return match decode_refusal(&error) {
                Ok(refusal) => refuse(context, refusal),
                Err(typed) => Err(typed),
            };
        }
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    let message = match message(&value) {
        Ok(message) => message,
        Err(refusal) => return refuse(context, refusal),
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    if let Err(refusal) = lexical(message.query, &context.limits) {
        return refuse(context, refusal);
    }
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    let Ok(document) = parse_query(message.query) else {
        return refuse(context, Refusal::malformed());
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    let operation = match selected_operation(&document, message.operation_name) {
        Ok(operation) => operation,
        Err(refusal) => return refuse(context, refusal),
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    if let Err(refusal) = check_fragment_graph(&document, &operation.selection_set.node, context.limits.lexical_tokens) {
        return refuse(context, refusal);
    }
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }
    let expansion = match count_expansion(&document, operation, &context.limits) {
        Ok(expansion) => expansion,
        Err(refusal) => return refuse(context, refusal),
    };
    if let Err(refusal) = boundary(context, deadline) {
        return refuse(context, refusal);
    }

    let exceeded = Arc::new(AtomicBool::new(false));
    let cost_gate = CostGate {
        cost: expansion.cost,
        limit: context.limits.resolver_work,
        exceeded: exceeded.clone(),
    };
    let schema = Schema::build(ControlQuery, ControlMutation, EmptySubscription)
        .extension(cost_gate)
        .finish();
    let run = StartRun {
        inputs: context.start.clone(),
        cancelled: context.cancelled.clone(),
        deadline,
        edition: context.edition.clone(),
    };
    let mut request = Request::new(message.query).data(run);
    if let Some(name) = message.operation_name {
        request = request.operation_name(name);
    }
    let response = schema.execute(request).await;
    if exceeded.load(Ordering::Acquire) {
        return refuse(context, Refusal::unsupported(Some("resolver_work")));
    }
    if !response.errors.is_empty() {
        return refuse(context, Refusal::invalid());
    }
    present_with_replacement(context, || present_result(context, &response, &expansion))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::futures_util::FutureExt;
    use pn_interchange::Map;

    const DRAFT: &str = include_str!("../schema/control-register-draft.toml");

    fn limits() -> Limits {
        Limits {
            schema_source: 16_384,
            register_source: 16_384,
            graphql_source: 16_384,
            transport: 16_384,
            decoded_bytes: 16_384,
            decoded_items: 16_384,
            cbor_nesting: 32,
            input_nesting: 32,
            decoding_work: 65_536,
            lexical_tokens: 4_096,
            source_nesting: 32,
            selection_depth: 16,
            root_selections: 16,
            fields: 4_096,
            aliases: 4_096,
            fragment_work: 4_096,
            resolver_work: 1_024,
            response: 16_384,
            concurrency: 1,
            execution: 10_000_000_000,
            cancellation_drain: 1_000_000_000,
            shell_start: 1_000_000_000,
            shell_stop: 1_000_000_000,
            start_weight: 1,
        }
    }

    fn start() -> StartInputs {
        StartInputs {
            edition_supported: true,
            bootstrap_valid: true,
            cancelled: false,
            failures: StartFailures {
                resource_exhausted: false,
                start_failed: false,
            },
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn context(limits: Limits, start: StartInputs) -> ExecutionContext {
        ExecutionContext::unserved(limits, start).expect("positive explicit unserved caps")
    }

    fn run(bytes: &[u8], context: &ExecutionContext) -> Result<TransportMessage, EntryError> {
        execute(bytes, context)
            .now_or_never()
            .expect("immediate in-process control resolver")
    }

    fn request(query: &str) -> Vec<u8> {
        Value::Map(
            Map::new([(
                Value::Text(Text::from("query".to_owned())),
                Value::Text(Text::from(query.to_owned())),
            )])
            .expect("one text key"),
        )
        .to_canonical_bytes()
    }

    fn large_query(count: usize) -> String {
        use std::fmt::Write;
        let mut query = String::from("mutation { start { ");
        for index in 0..count {
            write!(&mut query, "a{index}: ready ").expect("String write");
        }
        query.push_str("} }");
        query
    }

    fn read(message: &TransportMessage) -> Value {
        let mut usage = TransportUsage::default();
        Value::from_transport_bytes(
            message.as_bytes(),
            TransportLimits {
                input_bytes: 65_536,
                allocation_bytes: 65_536,
                items: 65_536,
                depth: 64,
                nesting: 64,
                work: 262_144,
            },
            &mut usage,
        )
        .expect("emitted transport response is readable")
    }

    fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
        let Value::Map(map) = value else {
            panic!("expected map");
        };
        map.iter()
            .find(|(key, _)| matches!(key, Value::Text(text) if text.as_str() == name))
            .map(|(_, value)| value)
            .expect("named member")
    }

    fn error_class(message: &TransportMessage) -> (String, Option<String>) {
        let value = read(message);
        let Value::Array(errors) = member(&value, "errors") else {
            panic!("error array");
        };
        let error = &errors.as_slice()[0];
        let extension = member(error, "extensions");
        let Value::Text(class) = member(extension, "class") else {
            panic!("class text");
        };
        let ceiling = match member(extension, "ceiling") {
            Value::Text(text) => Some(text.as_str().to_owned()),
            Value::Null => None,
            _ => panic!("ceiling text or null"),
        };
        (class.as_str().to_owned(), ceiling)
    }

    fn start_result(message: &TransportMessage, root_name: &str) -> (bool, Option<String>) {
        let value = read(message);
        let result = member(member(&value, "data"), root_name);
        let Value::Bool(ready) = member(result, "ready") else {
            panic!("ready boolean");
        };
        let failure = match member(result, "failure") {
            Value::Text(text) => Some(text.as_str().to_owned()),
            Value::Null => None,
            _ => panic!("failure text or null"),
        };
        (*ready, failure)
    }

    /// Claim: The byte entry decodes one bounded CBOR request and dispatches start through the actual GraphQL schema.
    /// ´claim:executor:start-through-bytes´
    /// ´test:unit:start-through-bytes´
    #[test]
    fn start_through_bytes() {
        let state = start();
        let calls = state.count.clone();
        let context = context(limits(), state);
        let message = run(&request("mutation { start { ready edition failure } }"), &context).expect("start response");
        assert_eq!(start_result(&message, "start"), (true, None));
        assert_eq!(calls.load(Ordering::Acquire), 1, "actual resolver called once");
        let value = read(&message);
        let Value::Text(edition) = member(member(member(&value, "data"), "start"), "edition") else {
            panic!("edition text");
        };
        assert_eq!(edition.as_str(), EDITION);
    }

    /// Claim: A truncated transport message refuses as Malformed before resolver entry while its complete neighbour dispatches.
    /// ´claim:executor:malformed-message-refuses´
    /// ´test:unit:malformed-message-refuses´
    #[test]
    fn malformed_message_refuses() {
        let state = start();
        let calls = state.count.clone();
        let context = context(limits(), state);
        let complete = request("mutation { start { ready edition failure } }");
        let malformed = &complete[..complete.len() - 1];
        let message = run(malformed, &context).expect("bounded malformed error");
        assert_eq!(error_class(&message), ("Malformed".to_owned(), None));
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(run(&complete, &context).is_ok());
        assert_eq!(calls.load(Ordering::Acquire), 1);
        let bom = "\u{feff}mutation { start { ready } }";
        let escaped_block = r#"mutation { start(arg: """a \""" b""") { ready } }"#;
        for source in [bom, escaped_block] {
            assert!(lexical(source, &limits()).is_ok(), "valid lexical neighbour");
            assert!(parse_query(source).is_ok(), "dependency accepts lexical neighbour");
        }
    }

    /// Claim: A syntactically valid selected inspect or administer mutation refuses Unsupported before ordinary field validation.
    /// ´claim:executor:unsupported-operation-refuses´
    /// ´test:unit:unsupported-operation-refuses´
    #[test]
    fn unsupported_operation_refuses() {
        let state = start();
        let calls = state.count.clone();
        let context = context(limits(), state);
        for name in ["inspect", "administer"] {
            let message = run(&request(&format!("mutation {{ {name} }}")), &context).expect("unsupported message");
            assert_eq!(error_class(&message), ("Unsupported".to_owned(), None));
        }
        for source in ["mutation { start { ready } inspect }", "mutation { inspect start { ready } }"] {
            let message = run(&request(source), &context).expect("unsupported root in either order");
            assert_eq!(error_class(&message), ("Unsupported".to_owned(), None));
        }
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    /// Claim: Each pending synthetic register value and the embedded pending draft refuse context construction without serving an edition.
    /// ´claim:executor:pending-configuration-refuses´
    /// ´test:unit:pending-configuration-refuses´
    #[test]
    fn pending_configuration_refuses() {
        assert!(matches!(ExecutionContext::served(), Err(EntryError::LimitsUnadmitted)));
        let complete = DRAFT.replace("status = \"not-yet-admitted\"", "status = \"admitted\", value = 1");
        let marker = "status = \"admitted\", value = 1";
        let slots = complete.match_indices(marker).count();
        assert!(slots > 20);
        assert!(ExecutionContext::checked_unserved(&complete, limits(), start()).is_ok());
        for index in 0..slots {
            let at = complete.match_indices(marker).nth(index).expect("synthetic slot").0;
            let mut pending = complete.clone();
            pending.replace_range(at..at + marker.len(), "status = \"not-yet-admitted\"");
            assert!(matches!(
                ExecutionContext::checked_unserved(&pending, limits(), start()),
                Err(EntryError::LimitsUnadmitted)
            ));
        }
    }

    /// Claim: The decoder's allocation-byte ceiling refuses before work or an unbudgeted reservation.
    /// ´claim:executor:reservation-limit-precedes-work´
    /// ´test:unit:reservation-limit-precedes-work´
    #[test]
    fn reservation_limit_precedes_work() {
        let bytes = request("mutation { start { ready edition failure } }");
        let mut limits = limits();
        limits.decoded_bytes = 1;
        let context = context(limits.clone(), start());
        let message = run(&bytes, &context).expect("bounded decoder error");
        assert_eq!(
            error_class(&message),
            ("Unsupported".to_owned(), Some("decoded_bytes".to_owned()))
        );
        let mut usage = TransportUsage::default();
        assert!(matches!(
            Value::from_transport_bytes(&bytes, limits.transport_limits(), &mut usage),
            Err(DecodeError::TransportLimit {
                resource: "allocation bytes",
                ..
            })
        ));
        assert_eq!(usage.allocation_calls, 0, "refusal precedes reservation");
        for frame in [b"\x5f\x42ab\x41c\xff".as_slice(), b"\x9f\x01\x02\xff".as_slice()] {
            let mut sufficient = TransportUsage::default();
            let mut exact = limits.transport_limits();
            exact.allocation_bytes = 16_384;
            assert!(Value::from_transport_bytes(frame, exact, &mut sufficient).is_ok());
            assert!(sufficient.allocation_bytes > 0);
            exact.allocation_bytes = sufficient.allocation_bytes;
            assert!(
                Value::from_transport_bytes(frame, exact, &mut TransportUsage::default()).is_ok(),
                "exact reservation fits"
            );
            exact.allocation_bytes -= 1;
            let mut refused = TransportUsage::default();
            assert!(matches!(
                Value::from_transport_bytes(frame, exact, &mut refused),
                Err(DecodeError::TransportLimit {
                    resource: "allocation bytes",
                    ..
                })
            ));
            assert!(
                refused.allocation_bytes <= exact.allocation_bytes,
                "no over-budget reservation call"
            );
        }
    }

    /// Claim: A value-head depth excess refuses before GraphQL expansion, with root depth one.
    /// ´claim:executor:depth-limit-precedes-expansion´
    /// ´test:unit:depth-limit-precedes-expansion´
    #[test]
    fn depth_limit_precedes_expansion() {
        let bytes = request("mutation { start { ready edition failure } }");
        let mut limits = limits();
        limits.input_nesting = 1;
        let mut exact = limits.transport_limits();
        let context = context(limits, start());
        let message = run(&bytes, &context).expect("depth error");
        assert_eq!(
            error_class(&message),
            ("Unsupported".to_owned(), Some("input_nesting".to_owned()))
        );
        exact.depth = 2;
        assert!(Value::from_transport_bytes(&bytes, exact, &mut TransportUsage::default()).is_ok());
        exact.depth = 1;
        assert!(matches!(
            Value::from_transport_bytes(&bytes, exact, &mut TransportUsage::default()),
            Err(DecodeError::TransportLimit { resource: "depth", .. })
        ));
        let source = "# ignored until carriage return\rmutation { start { ready } }";
        assert!(parse_query(source).is_ok(), "dependency accepts carriage-return terminator");
        let mut source_limits = self::limits();
        source_limits.source_nesting = 1;
        assert_eq!(
            lexical(source, &source_limits),
            Err(Refusal::unsupported(Some("source_nesting")))
        );
        let message = run(&request(source), &self::context(source_limits, start())).expect("source depth error");
        assert_eq!(
            error_class(&message),
            ("Unsupported".to_owned(), Some("source_nesting".to_owned()))
        );
    }

    /// Claim: Decode work is an independent pre-dispatch ceiling; a sufficient work cap admits the same bytes.
    /// ´claim:executor:decoding-work-is-independent´
    /// ´test:unit:decoding-work-is-independent´
    #[test]
    fn decoding_work_is_independent() {
        let bytes = request("mutation { start { ready edition failure } }");
        let mut small = limits();
        small.decoding_work = 1;
        let message = run(&bytes, &context(small, start())).expect("work error");
        assert_eq!(
            error_class(&message),
            ("Unsupported".to_owned(), Some("decoding_work".to_owned()))
        );
        assert!(run(&bytes, &context(limits(), start())).is_ok());
    }

    /// Claim: Produced start data has ready exactly when failure is null across success and every closed failure name.
    /// ´claim:executor:result-invariant´
    /// ´test:unit:result-invariant´
    #[test]
    fn result_invariant() {
        let bytes = request("mutation { start { ready edition failure } }");
        for (kind, expected) in [
            (0, None),
            (1, Some("EditionUnsupported")),
            (2, Some("BootstrapInvalid")),
            (3, Some("Cancelled")),
            (4, Some("ResourceLimit")),
            (5, Some("StartFailed")),
        ] {
            let mut state = start();
            state.edition_supported = kind != 1;
            state.bootstrap_valid = kind != 2;
            state.cancelled = kind == 3;
            state.failures.resource_exhausted = kind == 4;
            state.failures.start_failed = kind == 5;
            let message = run(&bytes, &context(limits(), state)).expect("produced result");
            let (ready, failure) = start_result(&message, "start");
            assert_eq!(ready, failure.is_none());
            assert_eq!(failure.as_deref(), expected);
        }
        let mut simultaneous = start();
        simultaneous.edition_supported = false;
        simultaneous.bootstrap_valid = false;
        simultaneous.cancelled = true;
        simultaneous.failures.resource_exhausted = true;
        simultaneous.failures.start_failed = true;
        let message = run(&bytes, &context(limits(), simultaneous)).expect("first startup check");
        assert_eq!(start_result(&message, "start").1.as_deref(), Some("EditionUnsupported"));
        let mut simultaneous = start();
        simultaneous.cancelled = true;
        simultaneous.failures.resource_exhausted = true;
        simultaneous.failures.start_failed = true;
        let message = run(&bytes, &context(limits(), simultaneous)).expect("bounded startup cause order");
        assert_eq!(start_result(&message, "start").1.as_deref(), Some("Cancelled"));
    }

    /// Claim: Each of five closed message classes has its exact literal bytes, ordered maps, context edition and ceiling/null.
    /// ´claim:executor:message-error-bytes´
    /// ´test:unit:message-error-bytes´
    #[test]
    fn message_error_bytes() {
        const MALFORMED: &[u8] = b"\xa1\x66errors\x81\xa2\x67message\x78\x1cRequest syntax is malformed.\x6aextensions\xa3\x65class\x69Malformed\x67edition\x78\x6fschema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\x67ceiling\xf6";
        const INVALID: &[u8] = b"\xa1\x66errors\x81\xa2\x67message\x78\x1aRequest validation failed.\x6aextensions\xa3\x65class\x67Invalid\x67edition\x78\x6fschema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\x67ceiling\xf6";
        const UNSUPPORTED: &[u8] = b"\xa1\x66errors\x81\xa2\x67message\x78\x32Request exceeds the supported operation or limits.\x6aextensions\xa3\x65class\x6bUnsupported\x67edition\x78\x6fschema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\x67ceiling\xf6";
        const RESOURCE_LIMIT: &[u8] = b"\xa1\x66errors\x81\xa2\x67message\x78\x38Response cannot be completed within the declared limits.\x6aextensions\xa3\x65class\x6dResourceLimit\x67edition\x78\x6fschema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\x67ceiling\x68response";
        const CANCELLED: &[u8] = b"\xa1\x66errors\x81\xa2\x67message\x78\x26Request was cancelled before dispatch.\x6aextensions\xa3\x65class\x69Cancelled\x67edition\x78\x6fschema=org.peer-network.test.api-control-schema@1.0.0;register=org.peer-network.test.api-control-register@1.0.0\x67ceiling\xf6";
        let bytes = request("mutation { start { ready edition failure } }");
        let malformed = run(&bytes[..bytes.len() - 1], &context(limits(), start())).expect("malformed response");
        assert_eq!(malformed.as_bytes(), MALFORMED);
        let invalid_input = Value::Map(Map::new(std::iter::empty()).expect("empty map")).to_canonical_bytes();
        let invalid = run(&invalid_input, &context(limits(), start())).expect("invalid response");
        assert_eq!(invalid.as_bytes(), INVALID);
        let unsupported = run(&request("mutation { inspect }"), &context(limits(), start())).expect("unsupported response");
        assert_eq!(unsupported.as_bytes(), UNSUPPORTED);
        let mut small = limits();
        small.response = 800;
        let exhausted = run(&request(&large_query(50)), &context(small, start())).expect("replacement response");
        assert_eq!(exhausted.as_bytes(), RESOURCE_LIMIT);
        let cancelled = context(limits(), start());
        cancelled.cancelled.store(true, Ordering::Release);
        let cancelled = run(&bytes, &cancelled).expect("cancelled response");
        assert_eq!(cancelled.as_bytes(), CANCELLED);
    }

    /// Claim: An oversized aliased start result is discarded once and replaced under a fresh response budget without rerunning start.
    /// ´claim:executor:response-replacement-fits´
    /// ´test:unit:response-replacement-fits´
    #[test]
    fn response_replacement_fits() {
        let state = start();
        let calls = state.count.clone();
        let mut small = limits();
        small.response = 800;
        let message = run(&request(&large_query(50)), &context(small, state)).expect("fitting replacement");
        assert_eq!(
            error_class(&message),
            ("ResourceLimit".to_owned(), Some("response".to_owned()))
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(message.as_bytes().len() <= 800);
        let value = read(&message);
        let Value::Map(map) = value else {
            panic!("root map");
        };
        assert_eq!(map.len(), 1, "replacement has errors alone");
    }

    /// Claim: A positive cap that fits neither the result nor one replacement returns typed `ResponseLimit` and no bytes.
    /// ´claim:executor:response-nothing-fits´
    /// ´test:unit:response-nothing-fits´
    #[test]
    fn response_nothing_fits() {
        let state = start();
        let calls = state.count.clone();
        let mut tiny = limits();
        tiny.response = 1;
        assert!(matches!(
            run(
                &request("mutation { start { ready edition failure } }"),
                &context(tiny, state)
            ),
            Err(EntryError::ResponseLimit(EncodingError::Limit))
        ));
        assert_eq!(calls.load(Ordering::Acquire), 1, "start is never retried");
        assert!(matches!(
            present_with_replacement(&context(limits(), start()), || {
                Err(EntryError::ResponseLimit(EncodingError::Reservation))
            }),
            Err(EntryError::ResponseLimit(EncodingError::Reservation))
        ));
    }
}
