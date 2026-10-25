# Host transport · `guide:host:transport`

**Section (Host claims)** · `sec:host:area-host` If the transport boundary fails, service reachability or credentials can enter public driver state, or an unauthenticated service can supply storage results. The unpublished pn-host package supplies the transport evidence for (`[ROOT-dec:storage:secret-shim]`). The storage library and its schema are exercised only by tests; no executable opens a store. Independent review must admit the statement and result surface before executable persistence is enabled.

**Definition (Secret transport boundary)** · `def:host:transport-boundary` Configuration is acquired directly into fixed secret-owned storage after the public store-link case is checked. Only host-secured is implemented. Unix socket paths and numeric TCP endpoints are accepted; DNS resolution is held because this route does not give a resolver an ordinary hostname. Startup and SCRAM authenticate the real service before an in-process stream receives the upstream driver's public placeholder startup. The upstream client never receives the real backend cancellation key or session_authorization parameter.

**Implementation remark (Evidence limits)** · `impl:host:evidence-limits` The transport has a one-MiB message and configuration representation limit and a SCRAM iteration range of 4,096 through 100,000. The authentication password profile is printable ASCII. Unexpected diagnostics remain whole in a secret carrier and close the driver stream; the initial public diagnostic grammar admits fixed division-by-zero, query-cancellation and serialization-conflict messages. Startup parameters must match the checked public vocabulary, including the literal default search-path template; role-configured arbitrary strings cannot enter the driver parameter map. This is an explicit integration limit, not a claim to classify arbitrary server messages. (`[ROOT-open:design:secret-integrations]`) remains held for independent review of the complete evidence.

**Definition (Connection configuration)** · `def:host:connection-configuration` A store configuration acquired under the public host-secured link case.

**Rule (Secret acquisition)** · `rule:host:secret-acquisition` Acquire connection-only JSON without an intermediate public allocation.

**Definition (Refusal)** · `def:host:refusal` Bounded refusal causes contain no service-supplied strings or source errors.

**Definition (Private server diagnostic)** · `def:host:private-server-diagnostic` A whole, secret-typed server diagnostic; no string or serialization accessor.

**Definition (Session)** · `def:host:session` A secret-terminating connection. The storage module owns the closed statement vocabulary; no public item exposes the driver.

**Signature (Connect)** · `sig:host:connect` Authenticate the real service before constructing a public driver session.

**Signature (Fixture client)** · `sig:host:public-client` The raw client is crate-private and compiled only for tests. No production public item yields it; storage owns its closed statement vocabulary under (`[ROOT-amend:storage:closed-statements]`).

**Signature (Cancel)** · `sig:host:cancel` Cancel through the real secret-owned capability on a new shim transport.

**Signature (Private diagnostics)** · `sig:host:private-diagnostics` Take quarantined whole diagnostics without exposing their private bytes.

**Signature (Last relay refusal)** · `sig:host:last-refusal` Read the last fieldless relay cause. Either relay direction ending closes both driver-stream halves and releases the server session; storage observes end of stream and may inspect this bounded cause without retaining a driver diagnostic.

**Amendment (Measured authentication work)** · `amend:host:scram-ceiling` The iteration range in (`impl:host:evidence-limits`) is superseded by 4,096 through 600,000 inclusive, under (`[ROOT-amend:storage:measured-scram-ceiling]`).


**Section (History claims)** · `sec:history:area-history` A partial succession, rewritten edition or mixed boundary snapshot can change an earlier verdict or erase the evidence needed to reconstruct it. The shared contract roster establishes (`claim:history:atomic-effective-rows-preserve-earlier-verdicts`) in carrier scope, not admission of ledger or epoch semantics.

**Definition (Effective storage)** · `def:host:effective-storage` The library offers PostgresStore::open_store, load_boundary, append_effective_successor and audit_history, and the functional MemoryStore substitute, under (`[ROOT-sig:design:storage]`). Immutable versions retain family, public key, edition, announcement, opening, canonical payload bytes and commitments. Appended closure facts give exclusive ends. Withdrawal is an explicit absence-valued successor. A different complete version at an existing key and edition refuses with EditionConflict; identical content is idempotent. Six families are admitted: bound constants, opaque public rules, bound marker policies, validated lineage disclosures, validated burn publications and unsettled recognitions. Rule semantics remain the owning domain's duty. Recognition is never settlement. Payload constructors use validated records where a carrier exists and caller interchange values for opaque rules; the history contract checks interval and edition integrity without inventing domain admission.

**Open Question (Admitted epoch result)** · `open:host:admitted-epoch-result` The epoch implementer supplies the admitted ledger/result carrier in bite 5, with host integration in bite 8. Until then AdmittedEpoch is uninhabited and commit_admitted_epoch has no executable write body. The future transaction binds input references, immutable debit evidence and admitted result together or none; retry recognizes the same structural event before applying any debit. No partial result authorizes publication (`[ROOT-inv:storage:atomicity]`).


**Section (Declaration evidence)** · `sec:declarations:area-declarations` Persisting a later edition must not replace the exact constants selected at an earlier boundary. The narrower durable-carrier witness (`claim:declarations:canonical-storage-preserves-selected-constants`) cites (`[RECORDS-claim:declarations:effective-editions-preserve-historical-constants]`); it does not duplicate that mint.
