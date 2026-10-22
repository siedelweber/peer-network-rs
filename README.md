# Peer Network · `guide:foundation:overview`

**Section (xchg)** · `sec:foundation:area-xchg` If the interchange implementation fails, canonical byte equality or acceptance can disagree between producers and readers. The package pn-interchange at packages/interchange implements the adopted conventions; its concept (`spec:xchg:concept`), design (`spec:xchg:design`), audit (`rep:xchg:audit`) and commissioning (`rec:xchg:commissioning`) state its contracts and evidence.

**Section (toolchain)** · `sec:foundation:area-toolchain` If the compiler or build profile drifts from policy, the gate no longer establishes the intended build conditions. The decision (`rec:toolchain:decision`) fixes the nightly channel, absence of a minimum compiler and release profile.

## Design areas · `sec:foundation:design-areas`

**Section (design)** · `sec:foundation:area-design` If the implementation design fails, locally correct crates can disagree on public inputs, numerical verdicts or replay and cannot establish the concept as a whole. The design (`spec:design:implementation`) fixes contracts, mechanisms and the evidence required before their claims are implemented.

**Section (vision)** · `sec:foundation:area-vision` If the implementation concept fails, later packages can satisfy local contracts without delivering a complete, publicly recomputable epoch result. The concept (`spec:vision:concept`) states the purpose, obligations, boundaries, verification and phases of the whole implementation.

**Section (interchange)** · `sec:foundation:area-interchange` If interchange conformance fails, an external reader cannot determine a document's governing theory or acceptance. The conventions (`rec:interchange:decision`) fix that boundary and the implementation (`spec:xchg:concept`) supplies its canonical bytes and acceptance verdicts.

**Section (identity)** · `sec:foundation:area-identity` If identity adjudication fails, a digest can assert a role or assurance its recipe and consumer do not establish. The procedure (`rec:identity:decision`) classifies provenance, comparisons and proposed identities.

**Section (labels)** · `sec:foundation:area-labels` If label resolution fails, citations no longer identify one warranted environment in its declared owner. The calculus (`rec:labels:decision`) fixes the graph and its adoption data.

**Section (kinds)** · `sec:foundation:area-kinds` If kind classification fails, an environment head can claim a genre the declared relation does not recognize. The registry (`rec:kinds:decision`) and its enforced declaration render from one catalogue dataset.

**Section (decomposition)** · `sec:foundation:area-decomposition` If decomposition correspondence fails, crate responsibilities and dependency order lose their connection to the paper's named surfaces. The governing decision is (`rec:decomposition:decision`).

**Section (questions)** · `sec:foundation:area-questions` If question correspondence fails, a provisional reading can be mistaken for a settled implementation contract. The question register (`reg:questions:overview`) preserves the study readings and the maintainers' instructions.

**Section (inventory)** · `sec:foundation:area-inventory` If inventory correspondence fails, a normative statement or constant can disappear from implementation planning without an explicit scope decision. The inventory (`reg:inventory:overview`) preserves proposed homes and unresolved source data.

**Setup (Purpose)** · `setup:foundation:purpose` This workspace establishes the rules under which later packages and documents are developed. The decisions are collected in (`sec:records:index`). First-party code is licensed under AGPL-3.0-only; first-party documentation is dedicated to the public domain under CC0-1.0, as stated in the two root licence files. The [documents guide](packages/documents/README.md) carries the package claim area register.

**Rule (Editing)** · `rule:foundation:editing` Create `.lane` with `mkdir -p .lane` to hold redirected results. Edit document prose in `docs/templates` and repeated facts in `docs/inputs`. From the repository root, run `cargo run -p documents -- generate > .lane/generate.json`, then `cargo run -p documents -- write > .lane/write.json`, review the findings and commit the generated datasets and Markdown with their sources. A write exits with status three when it refreshed a file; a subsequent `cargo run -p documents -- check > .lane/check.json` must exit with status zero.

**Gate (Verification)** · `gate:foundation:verification` Run `bash ci/gate.sh` from the repository root with the tracked nightly toolchain, Python and the deployed linter available. `LINTER_BIN` selects the linter executable; its default is the compute deployment configured in the gate script. Each step reports its wall time and status and the final `GATE-EXIT` line reports status zero only when all steps pass. The gate writes generated files into its own checkout and requires a committed, clean tree; the standalone read-only checks do not refresh files.

**Rule (Pack provenance)** · `rule:vendor:pack` The first-party cli-common and execwrap packages began as the pack's crates at tag pack-0.2.0 under MIT OR Apache-2.0. The repository takes them under MIT and keeps the pack's copyright and permission notice in each package's LICENSE-MIT: [cli-common](packages/cli-common/LICENSE-MIT) and [execwrap](packages/execwrap/LICENSE-MIT). The packages with this repository's changes are maintained and distributed under AGPL-3.0-only as part of the repository's AGPL-3.0-only work. The pack carries no publicly resolvable identity, so this rule names its tag and no digest. Their workspace lint, formatting, feature and command-line policies are the same as other first-party packages.

**Rule (Interchange package provenance)** · `rule:vendor:interchange` The pn-interchange package was brought in whole from the first-party library cogra-interchange under AGPL-3.0-only and renamed. It is taken, maintained and distributed here under AGPL-3.0-only, as part of the repository distributed under AGPL-3.0-only. Its origin is not publicly fetchable, so this rule names no locator or commit.

**Rule (Vendored regular-expression engine)** · `rule:vendor:regexml` The engine at vendor/regexml is regexml 0.2.2 from https://github.com/Paligo/regexml, as extended by https://github.com/helping-kaiser/regexml on branch anchored-plus-budget at public commit feddb83dfdacceff2e81e86e7618ca31acccf910. The fork builds on upstream release regexml-v0.2.2 and adds the anchored Regex::is_full_match matcher, an operation budget, Regex::is_full_match_bounded and budget tests; the anchored exposure was proposed upstream as https://github.com/Paligo/regexml/pull/15. It arrived under Apache-2.0 OR MPL-2.0; the repository takes it under MPL-2.0, keeping LICENSE-MPL2, LICENSE-APACHE, COPYRIGHT and CREDITS.txt with the available source. Its files, including the scalar-alias substitution, remain under MPL-2.0 within the larger repository work distributed under AGPL-3.0-only. It does not inherit workspace lints. The copy is identical to that commit except twelve scalar generic arguments use a module-local CodePoint alias for char, declared once in each of src/analyze_string.rs (one), src/op_atom.rs (two), src/re_compiler.rs (three), src/re_matcher.rs (two), src/re_program.rs (three) and src/regex.rs (one), to avoid the repository-prohibited token without changing behaviour. Tests and snapshots are unchanged. Replace the vendored copy with the published crate when upstream releases both the anchored matcher and operation budget.

**Section (compatibility)** · `sec:foundation:area-compatibility` If compatibility policy fails, accidental early interfaces become unsupported promises or assigned interchange laws are weakened by a release policy. The decision (`rec:compatibility:decision`) governs all repository surfaces through (`rule:compatibility:pre-one`).

**Section (storage)** · `sec:foundation:area-storage` If storage fails, a later rule changes an earlier verdict or a partial write masquerades as durable admission. The decision (`rec:storage:decision`) fixes PostgreSQL and effective history separately from deployment operations; stored representations follow (`rule:compatibility:pre-one`).

**Section (observe)** · `sec:foundation:area-observe` If observability fails, work and resource loss become invisible or diagnostics change a binding result. (`rec:observe:decision`) requires labelled spans, metering, metrics and observation independence before the first domain crate; trace and metric names follow (`rule:compatibility:pre-one`).

**Section (testing)** · `sec:foundation:area-testing` If testing claims fail, passing suites can conceal unevidenced requirements or unsupported contracts. (`rec:testing:decision`) ties authored test-site statements and meaningful glosses to requirement coverage, execution results and explicit holds.

**Section (api)** · `sec:foundation:area-api` If the public API fails, callers can confuse a partial query with a published result, lose exact evidence bytes or repeat an uncertain submission. (`rec:api:decision`) separates typed CBOR requests from canonical documents and requires bounded, traced and claim-tested execution.

**Section (devnet)** · `sec:foundation:area-devnet` If development-network contracts fail, grants can be mistaken for destruction, history can count a burn twice, or test evidence can be mistaken for production assurance. (`rec:devnet:decision`) fixes the test-chain realization and bounded faucet.
