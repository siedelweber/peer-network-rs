# Wallet layout adapter · `guide:wallet:decoder`

**Section (Wallet claims)** · `sec:wallet:area-wallet` If public layout decoding drops a field or accepts an ambiguous target, chain evidence can be misattributed or a hostile length can exhaust the reader. The package exposes public transaction and block layout decoding and explicit evidence-output selection. It also exposes closed, bounded cookie-authenticated reads from the trusted same-host Elements service. It performs no signing, proof verification, custody or spending. The host edge requires development-network; the default host graph excludes this package.

**Definition (Decoder scope)** · `def:wallet:scope` The three labelled operations implement the layout portion of (`[ROOT-sig:design:devnet]`). An allocation-free framing pass checks complete consumption and aggregate lengths before maintained decoding. Transactions use elements' incremental decoder. Block headers use its existing header decoder only after complete bounded framing; non-evidence confidential, issuance and peg-in transactions retain their full layouts. Point and proof encoding parsing is not signature or proof verification. The public DTO carries opaque serialized subfields without minting a chain or semantic identity.

**Implementation remark (Measured limits)** · `impl:wallet:reservation-bound` Caller limits cannot exceed 4,000,000 encoded bytes, 4,096 aggregate entries, 10,000 script bytes or 65,536 bytes per witness/proof. The preflight envelope charges sixteen times encoded bytes, 15,360 bytes per declared entry and 4,194,304 bytes of fixed headroom, capped at 134,217,728 bytes. This is a conservative reservation admission rule, not a replacement global allocator or an enforced process RSS limit. The heap witness records actual requested and peak bytes per fixture, excluding profiler metadata, under (`[ROOT-amend:devnet:wallet-decoder-evidence]`).

**Implementation remark (Remaining integration)** · `impl:wallet:held-integration` Genesis RPC reads, signed fixtures, the settlement carrier and parser witnesses are scoped below; marker recognition and the settlement cases that need it remain held. The 100-byte OP_RETURN fixture carries three literal 32-byte fields for run, target and request; it establishes local exact-match selection only. The real-chain fixture relays it under the profile's declared 100-byte data-carrier size and the external producer constructs it; no transaction constructor enters pn-wallet. Global-context entropy-failure execution remains held; production decoder paths use the no-precomputation parsers and do not dereference the randomized global context. (`[ROOT-open:design:devnet-evidence]`) and (`[ROOT-open:crypto:dependency-admission]`) retain those integration duties.

**Definition (Decoder limits)** · `def:wallet:decoder-limits` Caller-supplied byte, aggregate item, script, witness and reservation limits are bounded by the implementation ceilings. Framing checks precede maintained decoding.

**Definition (Decoder refusal)** · `def:wallet:decoder-refusal` A fieldless cause distinguishes limits, count spelling, flags, incomplete or trailing input, codec refusal and unsupported evidence. No error owns input bytes.

**Definition (Transaction layout)** · `def:wallet:transaction-layout` The public field view retains version, lock time, every input and output, and their opaque serialized curve and proof fields.

**Definition (Validated layout)** · `def:wallet:validated-layout` Transaction owns a private field view, constructible in production builds only through complete bounded decoding; validation here means structural layout, not chain acceptance or cryptographic verification. The non-default fuzzing feature additionally exposes the bare codec projection for differential testing.

**Definition (Input layout)** · `def:wallet:input-layout` An input retains outpoint, peg-in flag, script, sequence, issuance presence and full serialized issuance and witness bytes.

**Definition (Output layout)** · `def:wallet:output-layout` An output retains complete serialized asset, value, nonce, script and witness bytes, including confidential non-evidence forms.

**Definition (Block layout)** · `def:wallet:block-layout` A block retains its complete header bytes and every decoded transaction; one non-evidence transaction does not disqualify the other layouts.

**Signature (Transaction fields)** · `sig:wallet:transaction-fields` Borrow the immutable already decoded view; pure access inherits its caller's observation.

**Signature (Decode transaction)** · `sig:wallet:decode-transaction` Preflight and decode exactly one complete transaction, refusing incomplete consumption or violated bounds.

**Signature (Decode block)** · `sig:wallet:decode-block` Preflight the entire block before allocation, then decode its complete header and all transaction layouts.

**Signature (Codec verdict)** · `sig:wallet:codec-verdict` The hidden fuzzing-only entry bypasses preflight, returns the bare codec verdict and first-party projection, and checks resource eligibility from decoded fields. Campaign callers bound input bytes before invoking this unbounded comparison surface; it is excluded from production defaults and the production observation census.

**Signature (Evidence amount)** · `sig:wallet:evidence-amount` Select a positive explicit integer amount in the requested asset, with no issuance or peg-in and an exact run, target and request script.

**Definition (Pinning successors)** · `def:wallet:pinning-successors` Chain evidence pins after 6 successor blocks, the depth of (`[ROOT-rule:devnet:settlement]`); the carrier fixes it rather than accepting a caller depth.

**Definition (Settlement evidence)** · `def:wallet:settlement-evidence` Located explicit evidence carries display-order transaction and block identifiers, its output index, the claimed height and the amount the evidence decoder selected.

**Definition (Settlement observation)** · `def:wallet:settlement-observation` One observation carries the active-chain tip, the block hashes the caller read at named heights and the located evidence, possibly reported more than once.

**Definition (Pending evidence)** · `def:wallet:pending-evidence` Evidence below the pinning depth carries its observed successor count; it is recomputed from every observation and never stored.

**Definition (Settlement view)** · `def:wallet:settlement-view` An admitted observation returns pinned evidence once per outpoint, pending evidence, the checked pinned total and the floor height with its hash.

**Definition (Settlement refusal)** · `def:wallet:settlement-refusal` Unavailable, stale, alias and overflow refusals leave the carrier unchanged; a fault names the conflicting floor height and the retained pinned total, and is returned for the rest of the run.

**Definition (Settlement carrier)** · `def:wallet:settlement` One run's carrier keeps pinned evidence by outpoint and any fault; its floor is the highest pinned event's height and block, derived from that evidence. It holds no marker policy, accepted set or snapshot.

**Signature (Settlement observation)** · `sig:wallet:settlement-observe` Check the floor, confirm each locator against the active-chain hash at its height, pin evidence at the declared depth and report the rest as pending, committing only a complete admitted observation.

**Amendment (Layout evidence)** · `amend:wallet:layout-evidence` The seven fixture obligations of (`[ROOT-verif:devnet:wallet-layout]`) are supported by (`claim:wallet:decoder-reservations-have-measured-bounds`), (`claim:wallet:explicit-evidence-binds-target-run-and-request`), (`claim:wallet:full-layouts-preserve-nonevidence-transactions`), (`claim:wallet:hostile-prefixes-refuse-before-codec-allocation`). The independent byte reader compares exposed fields of full layouts; per-vector heap tests measure the declared finite fixtures. Real-chain acceptance, relay policy and settlement remain outside this layout scope.

**Definition (RPC limits)** · `def:wallet:rpc-limits` Positive caller limits may lower the finite transport, JSON, chain-byte and deadline maxima in (`[ROOT-amend:devnet:rpc-bounds]`).

**Definition (RPC refusal)** · `def:wallet:rpc-refusal` Typed local causes contain no private error payload. Trusted service diagnostics remain public and complete. A decoder limit retains the block locator and exact limit and holds subsequent reads.

**Definition (RPC configuration)** · `def:wallet:rpc-config` Secret endpoint, port, relative cookie path and UID carriers accompany an operator-supplied trusted root descriptor. The configuration has role-only Debug and no Display implementation.

**Definition (RPC link)** · `def:wallet:rpc-link` HostSecured is the only admitted path case; choosing it binds the deployment assumption before acquisition.

**Definition (RPC read)** · `def:wallet:rpc-read` A closed enumeration selects the five declared read methods and fixed raw modes; no URL, method string or wallet selector is admitted.

**Definition (RPC result)** · `def:wallet:rpc-result` Exact height or display-order locator bytes, complete raw validated header, decoded block or transaction; no signature or chain-recognition verdict is minted.

**Definition (RPC client)** · `def:wallet:rpc-client` One instance owns one concurrent exchange slot and one rolling eight-attempt budget shared across its callers, including failed acquisition.

**Definition (RPC provisioning)** · `def:wallet:rpc-provisioning` The checked declaration names exact binary, chain, expected run, public configuration overrides, signing challenge and raw genesis. The trusted harness checks startup; the client checks the supported profile and raw genesis before returning a reader.

**Signature (RPC configuration)** · `sig:wallet:rpc-config` Transfer secret carriers and the trusted directory capability without formatting them.

**Signature (RPC client)** · `sig:wallet:rpc-client` Validate declarations and resource bounds, then check genesis locator and raw header through the same bounded transport. The two checks consume the normal attempt budget.

**Signature (RPC call)** · `sig:wallet:rpc-call` Perform one closed read with fresh cookie acquisition and one deadline. Return public typed data or refusal, retaining a decoder-limit hold and never automatically retrying.

**Amendment (Genesis transport scope)** · `amend:wallet:genesis-rpc` (`[ROOT-amend:devnet:wallet-rpc-evidence]`) records the real genesis service, separate producer credential and scoped parser, cookie and observation witnesses. Signed fixture blocks await a BDB-enabled Elements build; the remaining chain and settlement obligations stay held. The complete case censuses of (`[ROOT-verif:devnet:wallet-http]`), (`[ROOT-verif:devnet:wallet-json]`), (`[ROOT-verif:devnet:wallet-cookie]`), (`[ROOT-verif:devnet:wallet-secrets]`) are supported within this scope by (`[ROOT-claim:discipline:wallet-rpc-types-confine-private-authority]`), (`claim:wallet:generic-rpc-socket-retains-private-reachability`), (`claim:wallet:rpc-attempts-and-holds-are-shared`), (`claim:wallet:rpc-authentication-failures-are-secret-safe`), (`claim:wallet:rpc-cookie-descriptors-confine-acquisition`), (`claim:wallet:rpc-cookie-grammar-is-exact`), (`claim:wallet:rpc-cookie-rotation-has-no-replay`), (`claim:wallet:rpc-http-acquisition-is-bounded`), (`claim:wallet:rpc-http-framing-is-bounded`), (`claim:wallet:rpc-json-envelope-is-correlated`), (`claim:wallet:rpc-json-parser-is-exact-and-bounded`), (`claim:wallet:rpc-observation-retains-public-results-only`), (`claim:wallet:rpc-provisioning-rejects-mismatches`), (`claim:wallet:rpc-reads-have-closed-typed-projections`), (`claim:wallet:rpc-secret-carriers-do-not-format-inputs`).
