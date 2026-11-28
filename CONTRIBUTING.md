# Contributing · `guide:foundation:contributing`

Use this guide to find the repository's working rules, label forms and invariant statements. The cited text is the authority for each practice; the [record index](adr/README.md) collects the decisions (`sec:records:index`).

## Confidence in the code · `sec:foundation:contributing-confidence`

**Principle (Architecture and invariants)** · `prin:foundation:invariant-architecture` The code’s architecture exists to maintain the labelled invariants, and its design makes invariant checking easy and review clear, so the structure of the code exposes the properties it must preserve and the reasons they hold.

**Principle (Review as the main check)** · `prin:foundation:review-confidence` Code review is the main check: good, refactored code and a sound architecture matter more than a full test bed, because understandable structure and labelled review reasoning beside the code let a reviewer examine why the invariants hold. Debug assertions and tests contribute confidence alongside review.

**Rule (Labelled debug assertions)** · `rule:foundation:assertion-labels` Every debug assertion cites the label of the invariant it checks, a statement of kind inv in the records or in the labelled documentation of the code, so the check has an explicit property to preserve. The label linter tracks these citations by resolving them in the declared Markdown and Rust comment carriers under (`judg:labels:participation`) and the owner policies in .linter/; citation resolution does not establish that every debug assertion carries a citation or that its expression checks the cited invariant.

**Rule (Invariant tests)** · `rule:foundation:invariant-tests` Invariants are also tested by should-fail tests and mocks, so deliberately broken conditions exercise the checks that reject them.

**Rule (Coverage and edge cases)** · `rule:foundation:test-coverage` Tests are for code coverage and use mocks to exercise edge cases, so paths that ordinary operation rarely reaches are checked deliberately.

**Convention (Invariant predicates)** · `conv:foundation:invariant-predicates` In Rust, invariant checks are generally const fn predicates called by debug assertions, so the same predicate is available to checking and tests. The calling debug assertions are compiled out of release builds; const fn by itself does not remove a runtime call.

**Definition (Testing harness)** · `def:foundation:testing-harness` The testing harness is the part of the design whose primary role is to provide hooks through which invariant assertions can be tested easily with mocks, making controlled violations accessible without obscuring the code under review.

## Editing and checking a change · `sec:foundation:contributing-work`

Edit prose in `docs/templates` and repeated facts in `docs/inputs`, then generate the datasets and render the documents; review and commit the generated files together with their sources (`rule:foundation:editing`). The [README's editing rule](README.md) gives the implemented generate/render modes and report option; a completed report request is not evidence of a clean check. This guide is a literal template for a root Markdown document, rendered under (`dec:render:policy`) and (`cor:render:tradeoffs`).

Run the repository’s verification entry (`gate:foundation:verification`) after regeneration; it checks the retained code and tests, label declarations and document fixed point. A new tracked file needs its owner and resolving labels under (`rec:labels:decision`), but no build-graph registration or prepared-checker binding is required, because those mechanisms are no longer the adopted entry.

The [README’s verification entry](README.md) (`gate:foundation:verification`) owns the command, environment and success criterion.

## Labels and citations · `sec:foundation:contributing-labels`

The [label calculus](adr/001-label-calculus.md) fixes the forms in (`gram:labels:well-formed`), minting in (`inf:labels:mint`) and same-owner resolution in (`inf:labels:same-owner-citation`). Choose the kind by what the statement is, using the [kind registry](adr/002-environment-kinds.md), its relation (`sig:kinds:registry-data`) and (`inv:kinds:one-kind`); a guide, a section and a rule have different jobs.

These examples display the title's mint, a same-owner citation to it and a mention of it. They are fenced so they do not mint or cite again; the participation rule (`judg:labels:participation`) also explains why the doubled delimiters in the last example display a label without participating.

```text
Mint at this document's title:
# Contributing · `guide:foundation:contributing`

Same-owner citation from another ROOT-owned document:
Read the contributing guide (`guide:foundation:contributing`).

Mention of the label's spelling:
The displayed name is ``guide:foundation:contributing``.
```

## Finding invariant statements · `sec:foundation:contributing-invariants`

The table routes to statements of kind `inv` only, at their defining places. A property stated under another kind remains written authority where it stands: the kind relation (`sig:kinds:registry-data`) and (`inv:kinds:one-kind`) classify statements, rather than making this table a substitute for the other rules, requirements, laws or decisions. These routes cite existing places and adopt no proposal.

| Document | Place containing the invariant statements |
| --- | --- |
| [Label calculus](adr/001-label-calculus.md) | Invariants (`sec:labels:invariants`) |
| [Environment kinds](adr/002-environment-kinds.md) | Invariants (`sec:kinds:invariants`); Attestation (`sec:kinds:attestation`) |
| [Interchange conventions](adr/008-interchange-conventions.md) | Theories (`sec:interchange:theories`) |
| [Interchange design](adr/010-interchange-design.md) | Data language (`sec:xchg:data-language`) |
| [Durable storage](adr/015-durable-storage.md) | Record (`sec:storage:record`) |
| [Observability](adr/016-observability.md) | Record (`sec:observe:record`) |
| [Public API](adr/018-public-api.md) | Record (`sec:api:record`) |
| [Host intranet](adr/022-host-intranet.md) | Record (`sec:intranet:record`) |
| [Budgeting concept](docs/design/budgeting.md) | Admission and consumption (`sec:budget:admission`) |
| [Implementation design](docs/design/implementation.md) | Purpose (`sec:design:purpose`); Architecture (`sec:design:architecture`); Records (`sec:design:records`); Graph (`sec:design:graph`); Admission (`sec:design:admission`); Publication (`sec:design:publication`); Observability (`sec:design:observability`) |

| [Act and epoch documents](docs/design/act-epoch-concept.md) | (`inv:actepoch:static-closure`); (`inv:actepoch:independent-members`); (`inv:actepoch:part-separation`); (`inv:actepoch:type-placement`); (`inv:actepoch:no-extension`); (`inv:actepoch:witness-separation`); (`inv:actepoch:host-free-authorship`); (`inv:actepoch:reference-closure`); (`inv:actepoch:removal-neutrality`) |

**Rule (Invariant routes)** · `rule:foundation:contributing-invariant-routes` A change that mints a statement of kind `inv` in a place not routed by this table adds its route in the same change, so a reader can reach the new statement from this guide. A change that leaves a routed place with no statement of kind `inv` removes that route in the same change, so every route still leads to an invariant statement.
