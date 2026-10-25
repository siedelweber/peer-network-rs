//! The sole maintained-codec boundary; all inputs are public chain bytes.

/// Positive resource bounds applied before maintained-codec allocation.
/// (´def:wallet:decoder-limits´)
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded input bytes.
    pub bytes: usize,
    /// Aggregate collection entries, including nested witnesses.
    pub items: usize,
    /// Maximum bytes in one script.
    pub script: usize,
    /// Maximum bytes in one witness or proof.
    pub witness: usize,
    /// Conservative requested-allocation ceiling, excluding observation and allocator metadata.
    pub allocation: usize,
}

/// Bounded public refusal with no upstream error or input fragment.
/// (´def:wallet:decoder-refusal´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Invalid resource declaration.
    Limits,
    /// Encoded input exceeds its byte bound.
    Bytes,
    /// Collection count exceeds the aggregate budget.
    Items,
    /// The conservative total reservation envelope exceeds the caller's budget.
    Allocation,
    /// Script length exceeds its bound.
    Script,
    /// Witness length exceeds its bound.
    Witness,
    /// A field is truncated.
    Truncated,
    /// Bytes remain after the object.
    Trailing,
    /// A count uses a nonminimal encoding.
    Count,
    /// Invalid flag or discriminant.
    Flag,
    /// The maintained decoder refuses the framed object.
    Codec,
    /// Issuance and peg-in transactions are not evidence transactions.
    EvidenceInput,
    /// The output is missing, confidential or in a different asset.
    EvidenceOutput,
    /// The permanent destruction target has a different run/request binding.
    Target,
}

/// Public transaction fields; encoded subfields retain their complete layout.
/// (´def:wallet:transaction-layout´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionFields {
    /// Transaction version.
    pub version: u32,
    /// Complete inputs, including issuance and peg-in carriage.
    pub inputs: Vec<Input>,
    /// Complete outputs, including confidential non-evidence outputs.
    pub outputs: Vec<Output>,
    /// Consensus lock time.
    pub lock_time: u32,
}

/// A transaction whose complete framing and maintained decoding succeeded.
/// (´def:wallet:validated-layout´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction(TransactionFields);

impl Transaction {
    /// Immutable public fields; obtaining them cannot construct another validated layout.
    /// (´sig:wallet:transaction-fields´)
    #[doc = "Justified: Pure field access inherits the labelled decoder or evidence operation; it neither starts work nor records the whole transaction again."]
    #[must_use]
    pub fn fields(&self) -> &TransactionFields {
        &self.0
    }
}

/// Input fields, with opaque encoded proof carriage rather than a proof verdict.
/// (´def:wallet:input-layout´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    /// Transaction identifier and masked output index.
    pub outpoint: Vec<u8>,
    /// Peg-in flag.
    pub pegin: bool,
    /// Public script bytes.
    pub script: Vec<u8>,
    /// Consensus sequence.
    pub sequence: u32,
    /// Encoded issuance, including its nonce, entropy and both amounts.
    pub issuance: Vec<u8>,
    /// Whether the codec found a non-null issuance.
    pub has_issuance: bool,
    /// Complete encoded input witness.
    pub witness: Vec<u8>,
}

/// Output fields; commitment parsing does not establish a confidential amount.
/// (´def:wallet:output-layout´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    /// Encoded asset discriminant and value.
    pub asset: Vec<u8>,
    /// Encoded value discriminant and integer or commitment.
    pub value: Vec<u8>,
    /// Encoded nonce.
    pub nonce: Vec<u8>,
    /// Full public script bytes.
    pub script: Vec<u8>,
    /// Complete encoded output witness.
    pub witness: Vec<u8>,
}

/// Full block layout without a local signature or proof-verification verdict.
/// (´def:wallet:block-layout´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Complete original header, including signing challenge and witness.
    pub header: Vec<u8>,
    /// All transactions, not just evidence candidates.
    pub transactions: Vec<Transaction>,
}

fn project(tx: elements::Transaction) -> Transaction {
    use elements::encode::serialize;
    Transaction(TransactionFields {
        version: tx.version,
        lock_time: tx.lock_time.to_consensus_u32(),
        inputs: tx
            .input
            .into_iter()
            .map(|input| Input {
                outpoint: serialize(&input.previous_output),
                pegin: input.is_pegin,
                script: input.script_sig.as_bytes().to_vec(),
                sequence: input.sequence.to_consensus_u32(),
                issuance: serialize(&input.asset_issuance),
                has_issuance: !input.asset_issuance.is_null(),
                witness: serialize(&input.witness),
            })
            .collect(),
        outputs: tx
            .output
            .into_iter()
            .map(|output| Output {
                asset: serialize(&output.asset),
                value: serialize(&output.value),
                nonce: serialize(&output.nonce),
                script: output.script_pubkey.as_bytes().to_vec(),
                witness: serialize(&output.witness),
            })
            .collect(),
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    remaining: usize,
    limits: Limits,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: Limits) -> Result<Self, Refusal> {
        if limits.bytes == 0
            || limits.bytes > 4_000_000
            || limits.items == 0
            || limits.items > 4096
            || limits.script == 0
            || limits.script > 10_000
            || limits.witness == 0
            || limits.witness > 65_536
        {
            return Err(Refusal::Limits);
        }
        if bytes.len() > limits.bytes {
            return Err(Refusal::Bytes);
        }
        // The pinned codec reserves at most a one-MiB batch per active collection.
        // Each admitted entry is charged 64 KiB (including its C proof storage),
        // and each encoded byte sixteen times for decoding and public projection.
        let envelope = bytes
            .len()
            .checked_mul(16)
            .and_then(|n| limits.items.checked_mul(65_536).and_then(|items| n.checked_add(items)))
            .and_then(|n| n.checked_add(4_194_304))
            .ok_or(Refusal::Allocation)?;
        if limits.allocation == 0 || limits.allocation > 134_217_728 || envelope > limits.allocation {
            return Err(Refusal::Allocation);
        }
        Ok(Self {
            bytes,
            pos: 0,
            remaining: limits.items,
            limits,
        })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.pos.checked_add(n).ok_or(Refusal::Truncated)?;
        let value = self.bytes.get(self.pos..end).ok_or(Refusal::Truncated)?;
        self.pos = end;
        Ok(value)
    }

    fn count(&mut self) -> Result<usize, Refusal> {
        let tag = self.take(1)?[0];
        let (n, minimum) = match tag {
            253 => (
                u64::from(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| Refusal::Count)?)),
                253,
            ),
            254 => (
                u64::from(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| Refusal::Count)?)),
                65_536,
            ),
            255 => (
                u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| Refusal::Count)?),
                4_294_967_296,
            ),
            x => (u64::from(x), 0),
        };
        if n < minimum {
            return Err(Refusal::Count);
        }
        usize::try_from(n).map_err(|_| Refusal::Items)
    }

    fn entries(&mut self) -> Result<usize, Refusal> {
        let n = self.count()?;
        self.remaining = self.remaining.checked_sub(n).ok_or(Refusal::Items)?;
        Ok(n)
    }

    fn blob(&mut self, script: bool) -> Result<&'a [u8], Refusal> {
        let n = self.count()?;
        if n > if script { self.limits.script } else { self.limits.witness } {
            return Err(if script { Refusal::Script } else { Refusal::Witness });
        }
        self.take(n)
    }

    fn stack(&mut self) -> Result<(), Refusal> {
        for _ in 0..self.entries()? {
            self.blob(false)?;
        }
        Ok(())
    }

    fn confidential(&mut self, kind: u8) -> Result<(), Refusal> {
        let prefix = self.take(1)?[0];
        let length = match (kind, prefix) {
            (_, 0) => 0,
            (1, 1) => 8,
            (0, 1 | 10 | 11) | (1, 8 | 9) | (2, 1 | 2 | 3) => 32,
            _ => return Err(Refusal::Flag),
        };
        self.take(length)?;
        Ok(())
    }

    fn transaction(&mut self) -> Result<(), Refusal> {
        self.take(4)?;
        let flag = self.take(1)?[0];
        if flag > 1 {
            return Err(Refusal::Flag);
        }
        let inputs = self.entries()?;
        for _ in 0..inputs {
            self.take(32)?;
            let index = u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| Refusal::Truncated)?);
            self.blob(true)?;
            self.take(4)?;
            if index != u32::MAX && index & 0x8000_0000 != 0 {
                self.take(64)?;
                self.confidential(1)?;
                self.confidential(1)?;
            }
        }
        let outputs = self.entries()?;
        for _ in 0..outputs {
            self.confidential(0)?;
            self.confidential(1)?;
            self.confidential(2)?;
            self.blob(true)?;
        }
        self.take(4)?;
        if flag == 1 {
            for _ in 0..inputs {
                self.blob(false)?;
                self.blob(false)?;
                self.stack()?;
                self.stack()?;
            }
            for _ in 0..outputs {
                self.blob(false)?;
                self.blob(false)?;
            }
        }
        Ok(())
    }

    fn parameters(&mut self) -> Result<(), Refusal> {
        match self.take(1)?[0] {
            0 => {}
            1 => {
                self.blob(true)?;
                self.take(4)?;
                self.take(32)?;
            }
            2 => {
                self.blob(true)?;
                self.take(4)?;
                self.blob(true)?;
                self.blob(true)?;
                self.stack()?;
            }
            _ => return Err(Refusal::Flag),
        }
        Ok(())
    }

    fn header(&mut self) -> Result<(), Refusal> {
        let version = u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| Refusal::Truncated)?);
        self.take(72)?;
        if version & 0x8000_0000 == 0 {
            self.blob(true)?;
            self.blob(true)?;
        } else {
            self.parameters()?;
            self.parameters()?;
            self.stack()?;
        }
        Ok(())
    }
}

/// Decode a complete public transaction after an allocation-free framing pass.
/// (´sig:wallet:decode-transaction´)
///
/// # Errors
/// Refuses malformed, incomplete, trailing or over-limit input with a bounded cause.
#[tracing::instrument(
    name = "sig:design:devnet",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "sig:design:devnet",
        operation = "decode-transaction",
        source_item = "decoder::decode_transaction"
    ),
    ret
)]
pub fn decode_transaction(bytes: &[u8], limits: Limits) -> Result<Transaction, Refusal> {
    let result = (|| {
        let mut reader = Reader::new(bytes, limits)?;
        reader.transaction()?;
        if reader.pos != bytes.len() {
            return Err(Refusal::Trailing);
        }
        let tx: elements::Transaction = elements::encoding::decode_from_slice(bytes).map_err(|_| Refusal::Codec)?;
        Ok(project(tx))
    })();
    if result.is_err() {
        tracing::info!(outcome = "refusal");
    }
    result
}

/// Decode all layouts in a block, applying aggregate bounds before codec allocations.
/// (´sig:wallet:decode-block´)
///
/// # Errors
/// Refuses malformed layouts, incomplete consumption or a declared limit violation.
#[tracing::instrument(
    name = "sig:design:devnet",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "sig:design:devnet",
        operation = "decode-block",
        source_item = "decoder::decode_block"
    ),
    ret
)]
pub fn decode_block(bytes: &[u8], limits: Limits) -> Result<Block, Refusal> {
    let result = (|| {
        let mut reader = Reader::new(bytes, limits)?;
        reader.header()?;
        let header_end = reader.pos;
        let count = reader.entries()?;
        let transactions_start = reader.pos;
        for _ in 0..count {
            reader.transaction()?;
        }
        if reader.pos != bytes.len() {
            return Err(Refusal::Trailing);
        }
        let header: elements::BlockHeader = elements::encode::deserialize(&bytes[..header_end]).map_err(|_| Refusal::Codec)?;
        drop(header);
        let mut cursor = transactions_start;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let mut tx_reader = Reader::new(&bytes[cursor..], limits)?;
            tx_reader.transaction()?;
            let tx = elements::encoding::decode_from_slice(&bytes[cursor..cursor + tx_reader.pos]).map_err(|_| Refusal::Codec)?;
            transactions.push(project(tx));
            cursor += tx_reader.pos;
        }
        Ok(Block {
            header: bytes[..header_end].to_vec(),
            transactions,
        })
    })();
    if result.is_err() {
        tracing::info!(outcome = "refusal");
    }
    result
}

/// Select only explicit evidence with a permanent `OP_RETURN` run/request target.
/// (´sig:wallet:evidence-amount´)
///
/// # Errors
/// Refuses unsupported evidence forms, a different asset or an absent or different target.
#[tracing::instrument(
    name = "sig:design:devnet",
    fields(
        execution_owner = "WALLET",
        claim_owner = "ROOT",
        claim_label = "sig:design:devnet",
        operation = "evidence-amount",
        source_item = "decoder::evidence_amount"
    ),
    ret
)]
pub fn evidence_amount(
    tx: &Transaction,
    index: usize,
    asset: &[u8; 32],
    run: &[u8; 32],
    target: &[u8; 32],
    request: &[u8; 32],
) -> Result<u64, Refusal> {
    let result = (|| {
        let tx = &tx.0;
        if tx.inputs.iter().any(|input| input.pegin || input.has_issuance) {
            return Err(Refusal::EvidenceInput);
        }
        let output = tx.outputs.get(index).ok_or(Refusal::EvidenceOutput)?;
        if output.asset.first() != Some(&1)
            || output.asset.get(1..) != Some(asset.as_slice())
            || output.value.len() != 9
            || output.value[0] != 1
            || output.nonce != [0]
        {
            return Err(Refusal::EvidenceOutput);
        }
        let script = &output.script;
        if script.len() != 100
            || script[..2] != [0x6a, 0x20]
            || script[34] != 0x20
            || script[67] != 0x20
            || script[2..34] != *run
            || script[35..67] != *target
            || script[68..] != *request
        {
            return Err(Refusal::Target);
        }
        let amount = u64::from_be_bytes(output.value[1..].try_into().map_err(|_| Refusal::EvidenceOutput)?);
        if amount == 0 {
            return Err(Refusal::EvidenceOutput);
        }
        Ok(amount)
    })();
    if result.is_err() {
        tracing::info!(outcome = "refusal");
    }
    result
}

#[cfg(test)]
mod tests {
    /// Claim: Concurrent first dereferences of the admitted global context return the same process-lifetime context; this performs initialization only, with no signing or key-bearing operation.
    /// ´claim:wallet:global-context-initializes-once´
    /// ´test:unit:global-context-initialization´
    #[test]
    fn global_context_initialization() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    &**elements::secp256k1_zkp::SECP256K1
                })
            })
            .collect();
        let contexts: Vec<_> = threads.into_iter().map(|thread| thread.join().unwrap()).collect();
        for context in &contexts {
            assert!(std::ptr::eq(*context, contexts[0]));
        }
    }
}
