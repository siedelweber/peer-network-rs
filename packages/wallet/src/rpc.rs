//! Closed, secret-owning reads from the provisioned trusted Elements service.
use crate::{rpc_cookie, rpc_http, rpc_json, rpc_secret::Buffer};
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use std::{
    collections::VecDeque,
    fmt,
    net::{IpAddr, SocketAddr, TcpStream},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Positive finite resource ceilings declared before acquisition or connection.
/// (´def:wallet:rpc-limits´)
#[derive(Clone, Copy, Debug)]
pub struct RpcLimits {
    /// Complete outbound request, including authorization.
    pub request_bytes: usize,
    /// Complete response headers.
    pub header_bytes: usize,
    /// Response header fields.
    pub header_count: usize,
    /// Encoded JSON response bytes.
    pub response_bytes: usize,
    /// JSON nesting depth, counting the envelope.
    pub json_depth: usize,
    /// Aggregate JSON values and object keys.
    pub json_items: usize,
    /// Public decoded chain bytes.
    pub chain_bytes: usize,
    /// One monotonic budget from cookie acquisition through typed decoding.
    pub deadline: Duration,
}

impl Default for RpcLimits {
    /// Justified: Returning the declared finite constants is pure setup inherited by the RPC operation, which records its configured limits.
    fn default() -> Self {
        Self {
            request_bytes: 4096,
            header_bytes: 8192,
            header_count: 64,
            response_bytes: 8_001_024,
            json_depth: 16,
            json_items: 4096,
            chain_bytes: 4_000_000,
            deadline: Duration::from_secs(10),
        }
    }
}

impl RpcLimits {
    fn valid(self) -> bool {
        let cap = Self::default();
        [
            (self.request_bytes, cap.request_bytes),
            (self.header_bytes, cap.header_bytes),
            (self.header_count, cap.header_count),
            (self.response_bytes, cap.response_bytes),
            (self.json_depth, cap.json_depth),
            (self.json_items, cap.json_items),
            (self.chain_bytes, cap.chain_bytes),
        ]
        .into_iter()
        .all(|(value, max)| value > 0 && value <= max)
            && !self.deadline.is_zero()
            && self.deadline <= cap.deadline
    }
}

/// Public protocol or resource outcome; private transport errors never escape.
/// (´def:wallet:rpc-refusal´)
#[derive(Clone, Debug, PartialEq)]
pub enum RpcRefusal {
    /// Invalid declared configuration or limits.
    Configuration,
    /// Invalid cookie acquisition or representation; no private cause is retained.
    Cookie,
    /// Private socket operation failed.
    Transport,
    /// The single exchange deadline expired.
    Deadline,
    /// Another call owns the single exchange slot.
    Busy,
    /// Eight attempts in the preceding sixty seconds, before cookie access.
    Attempts,
    /// Request byte ceiling.
    RequestBytes,
    /// Header byte ceiling.
    HeaderBytes,
    /// Header count ceiling.
    HeaderCount,
    /// Response byte ceiling.
    ResponseBytes,
    /// Decoded chain byte ceiling.
    ChainBytes,
    /// Strict HTTP framing failed.
    Http,
    /// Authentication refused; body unread, cookie discarded, no retry.
    Authentication,
    /// A non-admitted public HTTP status.
    Status(u16),
    /// JSON syntax, resource or schema refusal.
    Json,
    /// JSON-RPC version, result/error choice or identifier mismatch.
    Correlation,
    /// Public diagnostic from the trusted service.
    Remote {
        /// Exact integer error code.
        code: i64,
        /// Complete public diagnostic.
        message: String,
        /// Complete bounded public diagnostic data.
        data: Option<serde_json::Value>,
    },
    /// Raw chain layout was refused.
    Decode(crate::Refusal),
    /// Reader held at the named public block because a decoder limit was reached.
    Held {
        /// Public block locator.
        block: [u8; 32],
        /// Exact decoder limit.
        limit: crate::Refusal,
    },
    /// Checked provisioning declaration or raw genesis differs.
    Provisioning,
}

impl fmt::Display for RpcRefusal {
    /// Justified: Only public typed outcomes and trusted public service diagnostics are formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RpcRefusal {}

/// Secret bootstrap values with role-only Debug and no Display implementation.
/// (´def:wallet:rpc-config´)
pub struct RpcConfig {
    link: RpcLink,
    endpoint: SecretString,
    port: SecretBox<u16>,
    cookie: SecretString,
    uid: SecretBox<u32>,
    root: std::fs::File,
}

/// The only admitted RPC path case; authentication of the peer belongs to deployment.
/// (´def:wallet:rpc-link´)
#[derive(Clone, Copy, Debug)]
pub enum RpcLink {
    /// Same-host, operator-secured path to the trusted Elements service.
    HostSecured,
}

impl RpcConfig {
    /// Transfer already-secret acquisition carriers into the client configuration.
    /// (´sig:wallet:rpc-config´)
    /// Justified: Secret carrier ownership transfer has no public payload to record.
    #[must_use]
    pub fn new(
        link: RpcLink,
        endpoint: SecretString,
        port: SecretBox<u16>,
        root: std::fs::File,
        cookie: SecretString,
        uid: SecretBox<u32>,
    ) -> Self {
        Self {
            link,
            endpoint,
            port,
            cookie,
            uid,
            root,
        }
    }
}

impl fmt::Debug for RpcConfig {
    /// Justified: Configuration formatting exposes only its role, never secret fields or descriptors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.link {
            RpcLink::HostSecured => f.write_str("RpcConfig { role: secret-bootstrap, link: host-secured }"),
        }
    }
}

/// Closed public read vocabulary; no arbitrary method, URL or wallet selector.
/// (´def:wallet:rpc-read´)
#[derive(Clone, Debug)]
pub enum Read {
    /// Current chain height.
    BlockCount,
    /// Locator at the given height.
    BlockHash(u64),
    /// Full raw header at the public locator.
    BlockHeader([u8; 32]),
    /// Full raw block at the public locator.
    Block([u8; 32]),
    /// Full raw transaction, located in a declared block.
    Transaction {
        /// Public transaction locator.
        transaction: [u8; 32],
        /// Public inclusion block locator.
        block: [u8; 32],
    },
}

/// Typed public read result with complete decoded layouts.
/// (´def:wallet:rpc-result´)
#[derive(Clone, Debug)]
pub enum ReadResult {
    /// Exact chain height.
    Count(u64),
    /// Display-order locator bytes.
    Hash([u8; 32]),
    /// Complete validated header encoding, without a signature verdict.
    Header(Vec<u8>),
    /// Complete block layout.
    Block(crate::Block),
    /// Complete transaction layout.
    Transaction(crate::Transaction),
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn unhex(value: &serde_json::Value, maximum: usize) -> Result<Vec<u8>, RpcRefusal> {
    let text = value.as_str().ok_or(RpcRefusal::Json)?;
    if text.len() % 2 != 0 {
        return Err(RpcRefusal::Json);
    }
    if text.len() / 2 > maximum {
        return Err(RpcRefusal::ChainBytes);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(RpcRefusal::Json),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

impl Read {
    fn arguments(&self) -> (&'static str, serde_json::Value) {
        use serde_json::json;
        match self {
            Self::BlockCount => ("getblockcount", json!([])),
            Self::BlockHash(height) => ("getblockhash", json!([height])),
            Self::BlockHeader(hash) => ("getblockheader", json!([hex(hash), false])),
            Self::Block(hash) => ("getblock", json!([hex(hash), 0])),
            Self::Transaction { transaction, block } => ("getrawtransaction", json!([hex(transaction), false, hex(block)])),
        }
    }

    /// A block refused at the response-byte ceiling is a declared byte limit
    /// like the decoder's: the reader holds there instead of skipping it.
    fn ceiling(&self, error: RpcRefusal) -> RpcRefusal {
        match (self, error) {
            (Self::Block(block), RpcRefusal::ResponseBytes) => RpcRefusal::Held {
                block: *block,
                limit: crate::Refusal::Bytes,
            },
            (_, error) => error,
        }
    }
}

#[derive(Default)]
struct State {
    attempts: VecDeque<Instant>,
    next_id: u64,
    held: Option<([u8; 32], crate::Refusal)>,
}

impl State {
    fn admit(&mut self, now: Instant) -> Result<u64, RpcRefusal> {
        if let Some((block, limit)) = self.held {
            return Err(RpcRefusal::Held { block, limit });
        }
        while self
            .attempts
            .front()
            .is_some_and(|start| now.saturating_duration_since(*start) >= Duration::from_secs(60))
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= 8 {
            return Err(RpcRefusal::Attempts);
        }
        self.attempts.push_back(now);
        self.next_id = self.next_id.checked_add(1).ok_or(RpcRefusal::Attempts)?;
        Ok(self.next_id)
    }
}

/// One service reader, one concurrent exchange, one shared rolling attempt budget.
/// (´def:wallet:rpc-client´)
pub struct RpcClient {
    config: RpcConfig,
    limits: RpcLimits,
    decode: crate::Limits,
    state: Mutex<State>,
}

impl RpcClient {
    /// Bind finite bounds and secret bootstrap before any file or socket acquisition.
    /// (´sig:wallet:rpc-client´)
    /// # Errors
    /// Refuses invalid limits, nonnumeric endpoints or a zero port.
    #[tracing::instrument(
        name = "sig:design:devnet",
        fields(
            execution_owner = "WALLET",
            claim_owner = "ROOT",
            claim_label = "sig:design:devnet",
            operation = "rpc-provisioning",
            rpc_link_case = "host-secured",
            source_item = "rpc::RpcClient::new"
        ),
        ret
    )]
    // Caveat: Endpoint text is borrowed only to check its byte length; the container has no length operation.
    // (´[ROOT-cav:observe:secret-wallet-rpc-new-1]´)
    // Caveat: Endpoint text is parsed into an ordinary IP address solely for validation and immediately discarded; the standard parser cannot accept the carrier.
    // (´[ROOT-cav:observe:secret-wallet-rpc-new-2]´)
    // Caveat: The port scalar is copied only for its nonzero validation comparison; the comparison cannot operate on the carrier.
    // (´[ROOT-cav:observe:secret-wallet-rpc-new-3]´)
    // Caveat: Cookie-path text is borrowed only to check its byte length; the container has no length operation.
    // (´[ROOT-cav:observe:secret-wallet-rpc-new-4]´)
    // Justified: Private endpoint, port and cookie path are inspected for configuration validity and the temporary parsed address is discarded; standard parsers require ordinary strings and scalars.
    #[allow(clippy::disallowed_methods)]
    pub fn new(
        config: RpcConfig,
        limits: RpcLimits,
        decode: crate::Limits,
        provisioning: &crate::Provisioning,
        run: &str,
    ) -> Result<Self, RpcRefusal> {
        if !limits.valid()
            || config.endpoint.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-new-1]´) */).len() > 64
            || config.endpoint.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-new-2]´) */).parse::<IpAddr>().is_err()
            || *config.port.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-new-3]´) */) == 0
            || config.cookie.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-new-4]´) */).len() > 4096
            || !crate::decoder::valid_limits(decode)
        {
            return Err(RpcRefusal::Configuration);
        }
        provisioning.check(run, decode)?;
        let client = Self {
            config,
            limits,
            decode,
            state: Mutex::new(State::default()),
        };
        if !provisioning.matches_hash(&client.read(Read::BlockHash(0))?) {
            return Err(RpcRefusal::Provisioning);
        }
        if !matches!(client.read(Read::BlockHeader(provisioning.genesis))?, ReadResult::Header(bytes) if bytes == provisioning.header)
        {
            return Err(RpcRefusal::Provisioning);
        }
        Ok(client)
    }

    /// Perform one closed read; refusals never trigger a retry or password fallback.
    /// (´sig:wallet:rpc-call´)
    /// # Errors
    /// Returns a typed protocol, service or limit refusal; held block readers remain held.
    #[tracing::instrument(
        name = "sig:design:devnet",
        fields(
            execution_owner = "WALLET",
            claim_owner = "ROOT",
            claim_label = "sig:design:devnet",
            operation = "rpc-read",
            source_item = "rpc::RpcClient::read"
        ),
        ret
    )]
    pub fn read(&self, request: Read) -> Result<ReadResult, RpcRefusal> {
        let start = Instant::now();
        let (method, params) = request.arguments();
        let mut status = None;
        let mut result_bytes = 0;
        let result = (|| {
            let mut state = self.state.try_lock().map_err(|_| RpcRefusal::Busy)?;
            let id = state.admit(start)?;
            let deadline = start.checked_add(self.limits.deadline).ok_or(RpcRefusal::Configuration)?;
            let value = self
                .exchange(method, &params, id, deadline, &mut status, &mut result_bytes)
                .map_err(|error| request.ceiling(error));
            let result = match value {
                Ok(value) => self.project(&request, &value),
                Err(error @ RpcRefusal::Held { .. }) => Err(error),
                Err(error) => return Err(error),
            };
            if let Err(RpcRefusal::Held { block, limit }) = &result {
                state.held = Some((*block, *limit));
            }
            rpc_http::remaining(deadline)?;
            result
        })();
        tracing::info!(method, status = ?status, elapsed_ns = start.elapsed().as_nanos(), result_bytes,
            outcome = if result.is_ok() { "success" } else { "refusal" });
        if let Err(cause) = &result {
            tracing::warn!(method, status=?status, elapsed_ns=start.elapsed().as_nanos(), result_bytes, cause=?cause, outcome="refusal");
        }
        result
    }

    // Caveat: The private cookie path is borrowed by secure file acquisition until that call returns; filesystem calls require ordinary path bytes.
    // (´[ROOT-cav:observe:secret-wallet-rpc-exchange-1]´)
    // Caveat: The expected owner scalar is copied into cookie ownership validation for that call; filesystem metadata comparisons require an ordinary user identifier.
    // (´[ROOT-cav:observe:secret-wallet-rpc-exchange-2]´)
    // Caveat: The private endpoint is parsed into an ordinary IP address used by connect during this exchange; the socket API cannot accept the carrier and socket state retains private reachability until close.
    // (´[ROOT-cav:observe:secret-wallet-rpc-exchange-3]´)
    // Caveat: The private port is copied into the ordinary socket address for connect; the socket API cannot accept the carrier and socket state retains private reachability until close.
    // (´[ROOT-cav:observe:secret-wallet-rpc-exchange-4]´)
    // Justified: The cookie acquisition and connect APIs require private path bytes, owner identity and an ordinary socket address; they are used within this exchange and are never attached to diagnostics.
    #[allow(clippy::disallowed_methods)]
    fn exchange(
        &self,
        method: &str,
        params: &serde_json::Value,
        id: u64,
        deadline: Instant,
        status: &mut Option<u16>,
        result_bytes: &mut usize,
    ) -> Result<serde_json::Value, RpcRefusal> {
        let cookie = rpc_cookie::acquire(
            &self.config.root,
            self.config.cookie.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-exchange-1]´) */).as_bytes(),
            *self.config.uid.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-exchange-2]´) */),
        )?;
        rpc_http::remaining(deadline)?;
        let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .map_err(|_| RpcRefusal::Json)?;
        let mut credential = Buffer::new(self.limits.request_bytes);
        credential.append(b"Basic ")?;
        cookie.encode_basic(&mut credential)?;
        drop(cookie);
        let length = body.len().to_string();
        // Account the exact serialized request before connecting: the request line,
        // five lowercase `name: value` fields, the blank line and the body.
        let fields = [
            ("host", "localhost".len()),
            ("connection", "close".len()),
            ("content-type", "application/json".len()),
            ("authorization", credential.len()),
            ("content-length", length.len()),
        ];
        let size = "POST / HTTP/1.1\r\n".len()
            + fields.iter().map(|(name, value)| name.len() + value + 4).sum::<usize>()
            + 2
            + body.len();
        if size > self.limits.request_bytes {
            return Err(RpcRefusal::RequestBytes);
        }
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/")
            .header(hyper::header::HOST, "localhost")
            .header(hyper::header::CONNECTION, "close")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::AUTHORIZATION, credential.header()?)
            .header(hyper::header::CONTENT_LENGTH, length)
            .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
            .map_err(|_| RpcRefusal::Http)?;
        drop(credential);
        let endpoint = self
            .config
            .endpoint
            .expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-exchange-3]´) */)
            .parse::<IpAddr>()
            .map_err(|_| RpcRefusal::Configuration)?;
        let stream = TcpStream::connect_timeout(
            &SocketAddr::new(
                endpoint,
                *self.config.port.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-exchange-4]´) */),
            ),
            rpc_http::remaining(deadline)?,
        )
        .map_err(|_| RpcRefusal::Transport)?;
        let (code, response) = rpc_http::exchange(stream, request, self.limits, deadline, status)?;
        *status = Some(code);
        let value = rpc_json::parse(&response, self.limits.json_depth, self.limits.json_items)?;
        *result_bytes = value
            .get("result")
            .or_else(|| value.get("error"))
            .map_or(0, |value| value.to_string().len());
        rpc_json::envelope(value, code, id)
    }

    fn project(&self, request: &Read, value: &serde_json::Value) -> Result<ReadResult, RpcRefusal> {
        match request {
            Read::BlockCount => value.as_u64().map(ReadResult::Count).ok_or(RpcRefusal::Json),
            Read::BlockHash(_) => Ok(ReadResult::Hash(unhex(value, 32)?.try_into().map_err(|_| RpcRefusal::Json)?)),
            Read::BlockHeader(_) => {
                let bytes = unhex(value, self.limits.chain_bytes)?;
                crate::decoder::decode_header(&bytes, self.decode).map_err(RpcRefusal::Decode)?;
                Ok(ReadResult::Header(bytes))
            }
            Read::Block(block) => {
                let bytes = unhex(value, self.limits.chain_bytes).map_err(|error| {
                    if error == RpcRefusal::ChainBytes {
                        RpcRefusal::Held {
                            block: *block,
                            limit: crate::Refusal::Bytes,
                        }
                    } else {
                        error
                    }
                })?;
                crate::decode_block(&bytes, self.decode)
                    .map(ReadResult::Block)
                    .map_err(|limit| {
                        if matches!(
                            limit,
                            crate::Refusal::Bytes
                                | crate::Refusal::Items
                                | crate::Refusal::Allocation
                                | crate::Refusal::Script
                                | crate::Refusal::Witness
                        ) {
                            RpcRefusal::Held { block: *block, limit }
                        } else {
                            RpcRefusal::Decode(limit)
                        }
                    })
            }
            Read::Transaction { .. } => crate::decode_transaction(&unhex(value, self.limits.chain_bytes)?, self.decode)
                .map(ReadResult::Transaction)
                .map_err(RpcRefusal::Decode),
        }
    }
}

impl fmt::Debug for RpcClient {
    /// Justified: Client formatting exposes a role marker, never bootstrap or socket state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RpcClient { role: chain-reader }")
    }
}

pub(crate) fn basic(bytes: &[u8], target: &mut Buffer) -> Result<(), RpcRefusal> {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        // Encoded credentials go directly into the erasing carrier.
        target.append(&[DIGITS[usize::from(a >> 2)]])?;
        target.append(&[DIGITS[usize::from(((a & 3) << 4) | (b >> 4))]])?;
        target.append(&[if part.len() > 1 {
            DIGITS[usize::from(((b & 15) << 2) | (c >> 6))]
        } else {
            b'='
        }])?;
        target.append(&[if part.len() > 2 { DIGITS[usize::from(c & 63)] } else { b'=' }])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decoder_limits() -> crate::Limits {
        crate::Limits {
            bytes: 4_000_000,
            items: 4096,
            script: 10_000,
            witness: 65_536,
            allocation: 134_217_728,
        }
    }
    fn client() -> RpcClient {
        RpcClient {
            config: RpcConfig::new(
                RpcLink::HostSecured,
                "127.0.0.1".into(),
                SecretBox::new(Box::new(1)),
                std::fs::File::open("/").unwrap(),
                "absent-private-cookie".into(),
                SecretBox::new(Box::new(0)),
            ),
            limits: RpcLimits::default(),
            decode: decoder_limits(),
            state: Mutex::new(State::default()),
        }
    }

    /// Claim: A shared rolling budget permits exactly eight attempts before any cookie access, refuses simultaneous callers, expires at sixty seconds, and retains the named decoder-limit hold.
    /// ´claim:wallet:rpc-attempts-and-holds-are-shared´
    /// ´test:unit:attempts-and-holds´
    #[test]
    fn attempts_and_holds() {
        let now = Instant::now();
        let mut state = State::default();
        for id in 1..=8 {
            assert_eq!(state.admit(now), Ok(id));
        }
        assert_eq!(state.admit(now + Duration::from_secs(59)), Err(RpcRefusal::Attempts));
        assert_eq!(state.admit(now + Duration::from_secs(60)), Ok(9));
        let reader = client();
        for _ in 0..8 {
            reader.state.lock().unwrap().admit(now).unwrap();
        }
        assert!(matches!(reader.read(Read::BlockCount), Err(RpcRefusal::Attempts)));
        let locked = reader.state.lock().unwrap();
        assert!(matches!(reader.read(Read::BlockCount), Err(RpcRefusal::Busy)));
        drop(locked);
        let mut state = reader.state.lock().unwrap();
        state.held = Some(([3; 32], crate::Refusal::Items));
        drop(state);
        assert_eq!(
            reader.read(Read::BlockCount).unwrap_err(),
            RpcRefusal::Held {
                block: [3; 32],
                limit: crate::Refusal::Items
            }
        );
    }

    /// Claim: Closed read operations select only the five declared raw-mode methods; typed projections refuse null and malformed hex, preserve decoded transactions and blocks, and identify a limiting block, including a block refused at the response-byte ceiling, without accepting unsupported routes.
    /// ´claim:wallet:rpc-reads-have-closed-typed-projections´
    /// ´test:unit:projections´
    #[test]
    fn projections() {
        let mut reader = client();
        let reads = [
            Read::BlockCount,
            Read::BlockHash(0),
            Read::BlockHeader([1; 32]),
            Read::Block([1; 32]),
            Read::Transaction {
                transaction: [2; 32],
                block: [1; 32],
            },
        ];
        assert_eq!(
            reads.iter().map(|read| read.arguments().0).collect::<Vec<_>>(),
            vec![
                "getblockcount",
                "getblockhash",
                "getblockheader",
                "getblock",
                "getrawtransaction"
            ]
        );
        for read in &reads {
            assert_eq!(reader.project(read, &serde_json::Value::Null).unwrap_err(), RpcRefusal::Json);
        }
        assert_eq!(reads[2].arguments().1[1], false);
        assert_eq!(reads[3].arguments().1[1], 0);
        assert_eq!(reads[4].arguments().1[1], false);
        for bad in ["a", "AA", "xx"] {
            assert_eq!(unhex(&serde_json::json!(bad), 32), Err(RpcRefusal::Json));
        }
        assert_eq!(unhex(&serde_json::json!("0011"), 1), Err(RpcRefusal::ChainBytes));
        let tx = include_bytes!("../fuzz/seeds/explicit-nonce");
        assert!(matches!(
            reader.project(&reads[4], &serde_json::json!(hex(tx))),
            Ok(ReadResult::Transaction(_))
        ));
        let block = include_bytes!("../fuzz/seeds/dynafed-block");
        assert!(matches!(
            reader.project(&reads[3], &serde_json::json!(hex(block))),
            Ok(ReadResult::Block(_))
        ));
        reader.decode.bytes = 1;
        assert_eq!(
            reader.project(&reads[3], &serde_json::json!(hex(block))).unwrap_err(),
            RpcRefusal::Held {
                block: [1; 32],
                limit: crate::Refusal::Bytes
            }
        );
        reader.limits.chain_bytes = 1;
        assert_eq!(
            reader.project(&reads[3], &serde_json::json!(hex(block))).unwrap_err(),
            RpcRefusal::Held {
                block: [1; 32],
                limit: crate::Refusal::Bytes
            }
        );
        assert_eq!(
            reads[3].ceiling(RpcRefusal::ResponseBytes),
            RpcRefusal::Held {
                block: [1; 32],
                limit: crate::Refusal::Bytes
            }
        );
        assert_eq!(reads[3].ceiling(RpcRefusal::Transport), RpcRefusal::Transport);
        for read in [&reads[0], &reads[1], &reads[2], &reads[4]] {
            assert_eq!(read.ceiling(RpcRefusal::ResponseBytes), RpcRefusal::ResponseBytes);
        }
        let limits = RpcLimits::default();
        assert!(limits.valid());
        assert!(!RpcLimits { json_items: 0, ..limits }.valid());
        assert!(
            !RpcLimits {
                deadline: Duration::ZERO,
                ..limits
            }
            .valid()
        );
        assert!(
            !RpcLimits {
                response_bytes: usize::MAX,
                ..limits
            }
            .valid()
        );
    }

    /// Claim: Basic encoding writes directly into an erasing buffer and leaves it only as a sensitive header value whose request formats a placeholder; configuration and client Debug retain only roles, and header, wire and parser refusals retain public causes without private input bytes.
    /// ´claim:wallet:rpc-secret-carriers-do-not-format-inputs´
    /// ´test:unit:secret-carriers´
    #[test]
    fn secret_carriers() {
        for (bytes, expected) in [
            (b"f".as_slice(), "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foobar", "Zm9vYmFy"),
        ] {
            let mut encoded = Buffer::new(32);
            basic(bytes, &mut encoded).unwrap();
            assert!(encoded.equals(expected.as_bytes()));
        }
        let mut encoded = Buffer::new(1);
        assert_eq!(basic(b"foo", &mut encoded), Err(RpcRefusal::RequestBytes));
        let reader = client();
        assert_eq!(format!("{reader:?}"), "RpcClient { role: chain-reader }");
        assert_eq!(
            format!("{:?}", reader.config),
            "RpcConfig { role: secret-bootstrap, link: host-secured }"
        );
        assert_eq!(format!("{encoded:?}"), "SecretRpcBuffer");
        // The Basic exit of (´[ROOT-cav:devnet:basic-header-exposure]´): the header value is
        // sensitive before any request holds it, the request formats only a placeholder, and
        // a credential the header grammar refuses leaves a typed cause without its bytes.
        let mut credential = Buffer::new(64);
        credential.append(b"Basic ").unwrap();
        basic(b"__cookie__:private", &mut credential).unwrap();
        assert!(credential.equals(b"Basic X19jb29raWVfXzpwcml2YXRl"));
        let header = credential.header().unwrap();
        assert!(header.is_sensitive());
        assert_eq!(format!("{header:?}"), "Sensitive");
        let request = hyper::Request::builder()
            .header(hyper::header::AUTHORIZATION, header)
            .body(())
            .unwrap();
        assert!(!format!("{request:?}").contains("X19jb29raWVfXzpwcml2YXRl"));
        let mut refused = Buffer::new(64);
        refused.append(b"Basic X19jb29r\n").unwrap();
        assert_eq!(refused.header().unwrap_err(), RpcRefusal::Cookie);
        assert_eq!(format!("{}", RpcRefusal::Cookie), "Cookie");
        assert!(std::error::Error::source(&RpcRefusal::Cookie).is_none());
        let private = b"HTTP/1.1 200 private_endpoint_sentinel\r\nprivate_cookie_sentinel\n\r\n";
        assert_eq!(crate::rpc_http::head(private, RpcLimits::default()), Err(RpcRefusal::Http));
        assert_eq!(
            crate::rpc_json::parse(b"{\"private_path_sentinel\":", 16, 4096),
            Err(RpcRefusal::Json)
        );
    }
}
