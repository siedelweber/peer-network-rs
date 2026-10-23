## Crate decomposition · `sec:decomposition:record`

**Record (Crate decomposition)** · `rec:decomposition:decision` Status: accepted. Scope: Paper correspondence, proposed crate boundaries and implementation order. Depends on: (`rec:labels:decision`), (`rec:kinds:decision`), (`rec:render:decision`), (`rec:output:decision`), (`rec:lint:decision`). Does not establish: The decomposition establishes no implementation or proof of the inventoried mathematics.

**Setup (Context)** · `setup:decomposition:context` A crate boundary needs a mathematical responsibility and a public input or output that can be reviewed independently. The statement inventory (`reg:inventory:overview`) assigns proposed homes without turning unresolved paper claims into implementation promises. Crate boundaries, dependency edges, encodings and bite order are engineering judgements adopted here; paper labels remain owned by the paper.

**Decision (Crates)** · `dec:decomposition:crates` The seven crates divide by computational responsibility. Records precede computation, publication has its own encoding boundary, and replay consumes public package bytes independently of the host's cached results. Independent replay orchestration does not claim an independently implemented numerical proof kernel. No domain crate is introduced by this record.

| Crate | Responsibility | Paper surfaces |
| --- | --- | --- |
| pn-records | Immutable public inputs: identities, acts, ledger/burn data and declared constants | ``def:graph:act-identifier`` ``def:graph:act-edge-projection`` ``def:comparator:burn-interface`` |
| pn-graph | Structural formation, shared graph algebra and title folds | ``post:nodes:canonical-tensor-pipeline`` ``def:graph:verified-act`` ``thm:graph:epoch-title-fold`` |
| pn-epoch | Compile and certify one final epoch state and its admission result | ``alg:epoch:conserved-standing-computation`` ``post:epoch:final-act-sequence-write-rule`` |
| pn-readouts | Expose published standing/title and optional exact raw views to terminal consumers | ``def:graph:raw-traversal-snapshot`` ``rem:network:taxonomy-subtleties`` |
| pn-host | Encode the complete seven-part public package | ``post:network:host-contract`` |
| pn-replay | Reconstruct and compare the binding package from public inputs | ``subsec:deployment:conserved-standing-reproducibility`` ``post:deployment:public-object-replay`` |
| pn-verification | Maintain labelled integrated fixtures and independent public-surface checks | ``rem:verification:certificate-reproducibility`` |

**Convention (Dependency graph)** · `conv:decomposition:dependencies` Each indented child is a direct dependency of its parent; the infrastructure edge follows (`amend:decomposition:publication`). The verification crate is a development-only consumer; its integrated fixtures never become a production dependency. Optional raw data may travel as nonbinding package data without making host encoding depend on the raw computation engine. The additional infrastructure dependencies and outer packages below follow (`amend:decomposition:infrastructure`); optional development edges are absent from non-development builds.

- pn-records
- pn-graph
  - pn-records
- pn-epoch
  - pn-records
  - pn-graph
- pn-readouts
  - pn-records
  - pn-graph
  - pn-epoch
- pn-host
  - pn-records
  - pn-graph
  - pn-epoch
  - pn-interchange (infrastructure)
  - reviewed PostgreSQL client (infrastructure)
  - pn-wallet (optional development-network feature) (infrastructure)
- pn-replay
  - pn-records
  - pn-graph
  - pn-epoch
  - pn-host
- pn-verification
  - pn-records
  - pn-graph
  - pn-epoch
  - pn-readouts
  - pn-host
  - pn-replay
- pn
  - pn-host
  - pn-records
  - pn-interchange
  - pn-readouts (optional)
- pn-wallet
  - reviewed Elements RPC client
- pn-client
  - pn-wallet
  - pn-records
  - pn-interchange
- pn-command
  - pn-client
  - pn
  - cli-common
- pn-testkit

**Decision (Numeric model)** · `dec:decomposition:numbers` Counts, identities, multiplicities and order positions remain exact discrete data. Declared finite ledger inputs and rational constants retain exact values; graph transcendental kernels and epoch solvers return outward enclosures. Every binding comparison is decided by an enclosure, never by an approximate iterate. The certificate encloses the evaluated width fence and its residual bound, rather than replacing that fence with a tighter shape-sensitive object. A threshold-straddling interval requires refinement or rejection under a specified indecision rule. Exact encoding of real-valued debits, equality witnesses and the numeric backend remain held until their contracts are settled; an interval is not silently rounded into a ledger value.

**Decision (Constants)** · `dec:decomposition:constants` Generate a pinned default module behind a read-only correspondence gate, with no hidden arithmetic in a build script. Check declaration identity, exact literal identity and certified computed-value evidence as distinct obligations. Every public package carries an effective-constants record identifying its edition, announced permitted overrides, effective boundary and reproduction evidence. Locked declarations do not acquire an override merely because they share a carrier with defaults. Illustrative threshold values cannot replace the epoch's computed schedule.

**Decision (Burn interface)** · `dec:decomposition:burn` The records crate owns public data for the burn-value map, opaque addresses, bootstrap capacity bound and unit-cost projection. A finite boundary sample covers every address the boundary reads; the host carries its edition and required provenance and settlement disclosures. The record makes no claim to implement a burn realization or prove destruction. Its motivating paper surface is ``def:comparator:burn-interface``.

**Decision (Package and replay)** · `dec:decomposition:encoding` Records, host package and replay remain three crates. The external publication package uses the canonical CBOR profile (`proto:design:encoding`) under (`rec:interchange:decision`), (`rec:xchg:concept-record`) and (`rec:xchg:design-record`), offered as the profile a deployment declares for Q04. This replaces the study's provisional UTF-8 JSON under (`amend:decomposition:publication`); deterministic ordering, exact values, complete references and explicit interval endpoints carry over. Reject duplicate fields, unknown binding variants and incomplete references. Q04 in (`reg:questions:overview`) remains a deployment choice; namespace allocation, the complete field theory and independent byte vectors remain prerequisites for compatibility claims (`open:design:publication-profile`). Representation of non-rational exact values also remains held. The seven-part package contains accepted acts and boundary facts; final ledger and debit vintages; semantic projection and base allocation; tilt, depth, emission, transport and rung verdicts; hull, certificate, enclosure, standing and admission; title, recognition and policy schedules; and formula/constant editions with reproduction evidence. Replay reconstructs these sections from disclosed inputs instead of relying on mutable lookups or hidden solver state. An externally consumed document of this repository follows the interchange conventions (`rec:interchange:decision`). Release support follows (`rule:compatibility:pre-one`).

**Amendment (Publication integration)** · `amend:decomposition:publication` The accepted proposals (`proposal:design:encoding`) and (`proposal:design:interchange-dependency`) amend (`dec:decomposition:encoding`) and (`conv:decomposition:dependencies`). The canonical CBOR profile satisfies the adopted external-document language while preserving the semantic package; pn-host depends on pn-interchange to reuse its canonical implementation, and pn-replay consumes the host's public decoding and profile surface. The accepted-study crate and bite datasets remain the original domain decomposition; this amendment supplies the infrastructure edge shown in the current dependency list. Domain boundaries and (`dec:decomposition:bites`) are unchanged. The canonical-encoding decision required by the original package-bite row is satisfied at repository level; the deployment declaration and profile-completion obligations remain explicit.

**Decision (Fixtures)** · `dec:decomposition:fixtures` Small computation fixtures live in their owning crates. The verification crate owns the integrated public-input corpus, independent small-case oracles and package replay checks. Certify the mathematical assertion before checking displayed rounding; stored decimal examples are not exact solver targets. A held or incompatible fixture is recorded as such and never counted as passing. No consensus, guild ranking, reward, bridge, CAN or licence-enforcement engine follows from this crate graph.

**Decision (Bite order)** · `dec:decomposition:bites` The eleven slices establish public records, constants, formation and title before the epoch compiler and certified solve, then admission, package and replay before optional raw services. Each slice writes its implementation decision, label mapping, exact fixture inputs and gate evidence. The integrated corpus grows alongside the slices and closes only after their public surfaces are covered.

| Order | Slice | Records and evidence | Dependency and hold | Paper labels |
| ---: | --- | --- | --- | --- |
| 1 | pn-records: identities and accepted act/edge envelopes | Study judgment: immutable act identity, author/source linkage, edge projection and explicit dependency data; label-to-field decision record and a complete-act counting fixture (``def:graph:act-identifier``) (``def:graph:act-edge-projection``) (``ver:standing:hyper-act-single-accounting``). | Study judgment: no computational dependency; establishes the smallest public input surface. Resolve the identity/projection question before locking its encoding. | ``def:graph:act-identifier`` ``def:graph:act-edge-projection`` ``ver:standing:hyper-act-single-accounting`` |
| 2 | pn-records: burn data, numeric representation and constants edition | Study judgment: sampled four-object burn record, exact declared inputs and typed constant definitions; dependency review, constant correspondence and override records (``def:comparator:burn-interface``) (``subsec:deployment:transparency-of-protocol-formulas``). | Study judgment: follows the basic record types; may instead precede the act slice; blocked numeric-library and real-debit decisions must be settled before accepted ledger values are encoded. | ``def:comparator:burn-interface`` ``subsec:deployment:transparency-of-protocol-formulas`` |
| 3 | pn-graph: geometry and formation | Study judgment: census, local formation checks, slices/tensors, determinant and parity; reference-geometry fixture record (``post:nodes:canonical-tensor-pipeline``) (``tbl:verification:reference-edges``) (``ver:tensors:opinion``). | Study judgment: consumes bite 1 records and bite 2 numeric/constant declarations. Pure fixture geometry can precede the ledger and solver. | ``post:nodes:canonical-tensor-pipeline`` ``tbl:verification:reference-edges`` ``ver:tensors:opinion`` |
| 4 | pn-graph: complete-act structural folds and title | Study judgment: verified complete acts, settlement recognition and title outputs; formation and title fixture record (``def:graph:verified-act``) (``post:epoch:settlement-standing-title-coupling``) (``ver:standing:title-coupling``). | Study judgment: requires records/census; produces the title inputs consumed by epoch recipient resolution. No terminal membership or revision-policy engine. | ``def:graph:verified-act`` ``post:epoch:settlement-standing-title-coupling`` ``ver:standing:title-coupling`` |
| 5 | pn-epoch: final ledger and standing compiler | Study judgment: final balances/counts/vintages, recipient resolutions, fold cells, coefficients, base allocation and emission; ledger, conservation and order-invariance fixture records (``eq:epoch:final-residual-balance``) (``def:epoch:standing-recipient-resolution``) (``ver:standing:epoch-permutation-invariance``). | Study judgment: requires bites 2–4; unresolved Invitation/domain/fold semantics hold the affected compiler case. | ``eq:epoch:final-residual-balance`` ``def:epoch:standing-recipient-resolution`` ``ver:standing:epoch-permutation-invariance`` |
| 6 | pn-epoch: certified numerical kernel and conserved solve | Study judgment: hull, activation enclosures, attempted-rung fence values, accepted rung, residual bounds and standing enclosure; numerical dependency and certificate fixture records (``def:dynamics:conserved-standing-certificate``) (``lem:dynamics:fixed-point-residual-enclosure``) (``ver:standing:conservation``). | Study judgment: requires the frozen compiler and ledger from bite 5; resolve certificate/indecision/current-fixture questions before treating a fixture as proof. | ``def:dynamics:conserved-standing-certificate`` ``lem:dynamics:fixed-point-residual-enclosure`` ``ver:standing:conservation`` |
| 7 | pn-epoch: final admission and schedules | Study judgment: action/epoch stamps, ``cond:epoch:write-own-balance-solvency``, ``cond:epoch:write-individual-safety`` and ``cond:epoch:write-epoch-admission``, door headroom and declared next-boundary schedules; gate and boundary-policy fixture records (``post:epoch:final-act-sequence-write-rule``) (``def:network:door-headroom``) (``def:epoch:safety-threshold``) (``ver:epoch:final-stamps``). | Study judgment: requires certified standing from bite 6 and a specified threshold-calibration rule; do not invent final-set search or consensus. | ``post:epoch:final-act-sequence-write-rule`` ``def:network:door-headroom`` ``def:epoch:safety-threshold`` ``ver:epoch:final-stamps`` |
| 8 | pn-host: canonical seven-part package | Study judgment: versioned serialized package, declared formulas/constants, attempted-rung evidence and complete public inputs; canonical-format and round-trip fixture records (``post:network:host-contract``) (``post:deployment:canonical-standing-publication``). | Study judgment: requires all binding outputs from bites 1–7 and a maintainer/deployment decision on canonical encoding. | ``post:network:host-contract`` ``post:deployment:canonical-standing-publication`` |
| 9 | pn-replay | Study judgment: independent reconstruction and section-by-section comparison results citing the owning paper claims; package reproduction and mutation-rejection fixture records (``subsec:deployment:conserved-standing-reproducibility``) (``post:deployment:public-object-replay``). | Study judgment: requires the package schema and computational public surfaces; no reverse dependency from pn-host. | ``subsec:deployment:conserved-standing-reproducibility`` ``post:deployment:public-object-replay`` |
| 10 | pn-readouts: optional raw publication service | Study judgment: derived raw Self snapshot, edge scalars and exact bounded traversal outputs; small-graph exhaustive path and terminal-input separation fixture records (``def:graph:raw-traversal-snapshot``) (``alg:epoch:exact-signed-raw-traversal``) (``rem:network:taxonomy-subtleties``). | Study judgment: requires published final standing and graph geometry; may move after bite 6 for a diagnostic prototype, but cannot feed standing. Resolve simple-path/walk semantics before asserting exact traversal. | ``def:graph:raw-traversal-snapshot`` ``alg:epoch:exact-signed-raw-traversal`` ``rem:network:taxonomy-subtleties`` |
| 11 | pn-verification: complete public-surface corpus | Study judgment: Appendix F claim/input/expected-enclosure records, held-claim register and end-to-end replay results; no invented passing outcomes (``rem:verification:numerical-rounding``) (``rem:verification:certificate-reproducibility``). | Study judgment: grows alongside each earlier bite as a leaf consumer; final corpus closure waits for every implemented public surface and all affected fixture questions. | ``rem:verification:numerical-rounding`` ``rem:verification:certificate-reproducibility`` |

**Consequence (Holds)** · `cor:decomposition:holds` The question register (`reg:questions:overview`) preserves the study readings beside the maintainers' classifications and instructions. Any bite whose behaviour depends on an open question for the paper's maintainers waits for its answer. The engineering recommendations do not resolve conflicts in identity, ledger debits, certificate or equality semantics, compiler multiplicity, threshold calibration, package representation, raw traversal or fixture expectations. Unaffected slices can proceed in dependency order. Numeric dependency versions and their proof contracts require review before the numeric bite; this record selects no library merely by naming a representation.

**Gate (Correspondence)** · `gate:decomposition:correspondence` The gate checks current input projections and rendered outputs, inventory uniqueness and totals, crate and bite structure, and label presentation under the declared import state. The paper registry uses the project-neutral namespace `class.linter.labels`, but its loader is not deployed yet; paper labels are exhibited, and inventory eligibility remains data for a compatible export format. No paper citation resolution is claimed. A document fixed point and a clean linter verdict establish correspondence discipline, not implementation of the inventoried mathematics.

**Amendment (Release support)** · `amend:decomposition:pre-one-007` Package, schema and interface evolution in (`dec:decomposition:encoding`) follows (`rule:compatibility:pre-one`), with assigned interchange majors governed by (`conv:compatibility:interchange`). The accepted storage slice and infrastructure additions are recorded in (`amend:decomposition:infrastructure`).

**Amendment (Infrastructure and bite refinement)** · `amend:decomposition:infrastructure` The accepted placements (`proposal:harness:packages`), (`proposal:design:storage-placement`), (`proposal:design:devnet-adapter`) and (`proposal:design:api-placement`) amend (`conv:decomposition:dependencies`) and refine the contents of (`dec:decomposition:bites`). The original study datasets, seven domain responsibilities and eleven-bite order remain intact. Outer infrastructure owns service, command and wallet effects rather than adding them to graph or epoch. Host storage starts early so history invariants are tested from their first use; its PostgreSQL client must pass (`open:design:secret-integrations`) before that slice lands. Only pn-wallet integrates Elements RPC, so chain inspection, settlement and faucet spending share one admitted boundary with client spending. pn-host's optional development-network feature enables its pn-wallet dependency; non-development builds omit the edge and runtime guards still refuse development operations. No node dependency on pn-client or pn-command is introduced, and replay consumes disclosed evidence without a live node. pn-testkit imports no production domain crate and production builds never import it; owning tests may use it as a development dependency. The added infrastructure roles and content refinements are rendered below from the accepted amendment data, with foundation shown as a prerequisite rather than a new domain bite.

| Infrastructure crate | Role | Direct prerequisites | Optional prerequisites |
| --- | --- | --- | --- |
| pn | Node schema, service and lifecycle | pn-host, pn-records, pn-interchange | pn-readouts |
| pn-wallet | Only Elements integration; chain evidence and wallet spending/recovery | reviewed Elements RPC client | None |
| pn-client | GraphQL node counterpart and client workflows | pn-wallet, pn-records, pn-interchange | None |
| pn-command | Node and client JSON command presentation | pn-client, pn, cli-common | None |
| pn-testkit | Development-only generic runners, models and mocks; no production imports | None | None |

| Slice | Accepted refinement |
| --- | --- |
| Before bite 1 | Foundation before bite 1: observability, claims, pn-testkit, harness and performance gates |
| 2 | Host storage slice and secret-preserving PostgreSQL integration; pn-wallet chain/RPC slice, host development edge, mocks and real-service suites |
| 5 | Pinned burn samples, immutable ledger vintages and storage evidence |
| 8 | Host publication; pn-interchange transport mode; pn node/API and local control; pn-wallet spending/recovery; pn-client and both pn-command surfaces; faucet |
| 9 | Independent package replay and client replay-input fetching without a live chain |
| 10 | Optional node readout edge and raw service |
| 11 | Complete supported integration corpus and evidence ledger |


**Amendment (Released wall and reference evidence)** · `amend:decomposition:wall-reference` The paper edition network-v0.26.3 refines (`dec:decomposition:numbers`), (`dec:decomposition:constants`), (`dec:decomposition:encoding`), (`dec:decomposition:fixtures`) and (`cor:decomposition:holds`). The reduced wall is primary and its numeraire image is the charged price; the deployment declares its fixed chartered structural floor before the first epoch (``def:epoch:safety-wall-floor``). The published controller reads the previous wall, completed width and accepted rung, applying its declared floor, deadband and cap; each epoch certifies on its own width, independently of controller performance (``def:epoch:wall-controller``, ``def:epoch:canonical-interim-wall-controller``, ``cond:epoch:safety-in-epoch-certification``). Escalation and future-width forecasts supply no certification. Bite 2 retains the floor, controller and exact comparison declarations; bite 6 verifies the conserved reference evidence; bite 7 implements the schedules and final gates; publication and replay retain the wall, proposal, delivered charge, width, fence and verdict in the existing semantic sections. This separates economic calibration and inter-epoch tracking from the mathematical safety claim rather than leaving an obsolete calibration hold over settled rules. The independent certificate ``ver:standing:conserved-equilibrium-enclosure`` closes the shared reference-input agreement frontier, not arbitrary-input or backend evidence; the retired staged verifier supplies no conserved result. The circulant comparison remains open under ``rem:dynamics:circulant-comparison-scope`` and cannot replace the proved fence. The design records the remaining owned work in (`open:design:wall-performance`), (`open:design:circulant-comparison`) and (`open:design:numeric-backend`). The original study rows remain historical decomposition evidence, with positional write-gate references expanded to their released labels; the current contracts are (`model:design:wall-floor`), (`alg:design:schedules`) and (`obs:design:reference-certificate`). Domain boundaries, dependencies and the eleven-bite order are unchanged.

**Amendment (Bite 1 entry evidence)** · `amend:decomposition:bite-one-entry-evidence` Adds mandatory entry conditions to (`gate:design:bite-1`). The entry obligations are (`gate:labels:implementation`), (`gate:xchg:concept-review`), (`gate:xchg:implementation`), (`dec:xchg:slice-sequencing`), (`req:interchange:fixed-once`). Before pn-records implementation starts, each held row below must have its named evidence admitted by its owner; current scoped test support is not a substitute for historical or consumer-specific evidence. The evidence gate refuses a packages/records directory while any of these entry rows remains held.

| Obligation | Owner | Evidence required before entry |
|---|---|---|
| (`gate:labels:implementation`) | Linter integration reviewer | Attach itemized deployed-linter conformance evidence for all implementation-gate clauses, including synthetic citations, anchor harvesting and traversal-order independence; a clean current corpus alone does not prove them. |
| (`gate:xchg:concept-review`) | Interchange contract reviewer | Record the itemized confirmation of purpose, consumers, completeness, scope and verification frame against the accepted conventions; test executions cannot retrospectively make that review. |
| (`gate:xchg:implementation`) | Interchange implementer and contract reviewer | Supply provenance for vector transcription and dependency verification at implementation start, alongside the now-present timing and regexp-guard evidence; current green tests do not establish historical order. |
| (`dec:xchg:slice-sequencing`) | Interchange contract reviewer | Reconcile the four historical implementation slices with their recorded sequence, or obtain an explicit amendment of that historical ordering condition. |
| (`req:interchange:fixed-once`) | Bite 1 implementer and interchange contract reviewer | Map every bite-1 interchange producer and reader to the one canonical contract and reject local convention alternatives before adding the first domain consumer. |

**Amendment (Entry admission fields)** · `amend:decomposition:entry-admission-fields` The entry rows of (`gate:design:bite-1`) under (`amend:decomposition:bite-one-entry-evidence`) each require an admission naming the same accountable owner, the evidence kind, admission status and the evidence received. All five remain held. Current-source scoped execution support and an explicit owner admission are both required; passing a generic claim alone does not clear historical or consumer-specific conditions. Either the conventional records directory or a workspace member named pn-records activates the refusal.
