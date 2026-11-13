# Interchange · `guide:interchange:overview`

**Setup (Evidence ownership)** · `setup:interchange:claims` This package owns its value, schema and registry claims under (`[ROOT-rec:testing:decision]`). Each area's entry states the risk of a failed claim; the entry is a local contract boundary, not evidence of a concept requirement. Item-specific gloss and stake review remains in the claims audit.

## Claim areas · `sec:interchange:areas`

**Amendment (Budgeted canonical validation)** · `amend:interchange:canonical-budget` The strict route required by (`[ROOT-amend:storage:canonical-values]`) and (`[ROOT-amend:storage:admitted-reads]`) validates through the existing decoder walk, borrows item spans and returns no owned value. The caller's allocation ceiling and fallible shared-meter callback must both admit every reservation before decoder usage is charged and the reservation executes; callback refusal retains usage for requests already made. No production limit or depth is selected. Evidence at the route's reservation site covers prior charging and exact reporting of its requests, not allocations that bypass the site. The absence of owned payload buffers, tag boxes and container-finalization allocations is a reviewed source property. Evidence owed before this route is used comprises differential acceptance and refusal classes over the canonical corpus and generated inputs, exact and one-below reservation controls, refusal at every reservation position of a nested input, borrowed-span controls, and assertion-failing mutants for an uncharged site, late charging, nonpreferred acceptance, missing refusal usage and ignored callback refusal. Existing canonical entry-point tests remain unchanged. Observation of the full public input through the information-level span is outside this budget; the repository subscriber's trace payload capture and queues have their separate bounds and loss accounting under (`[ROOT-amend:observe:emission-levels]`) and (`[ROOT-dec:observe:sinks]`), which do not bound formatting work by the read budget or establish a whole-process allocation ceiling. This statement records the required evidence, not an executed result or admission of the storage reader.


**Section (acceptance)** · `sec:interchange:area-acceptance` If acceptance claims fail, document stamps can select the wrong reader or turn a refusal into acceptance.


**Section (ast)** · `sec:interchange:area-ast` If syntax-tree claims fail, parsed distinctions can disappear before validation or printing.


**Section (cddl)** · `sec:interchange:area-cddl` If CDDL claims fail, schema acceptance can disagree with the declared label language or evaluable subset.


**Section (companion)** · `sec:interchange:area-companion` If companion claims fail, an earlier reader can receive a schema with unintended edits.


**Section (documents)** · `sec:interchange:area-documents` If document claims fail, malformed envelopes or unsupported values can cross the interchange boundary.


**Section (encoding)** · `sec:interchange:area-encoding` If encoding claims fail, equal values can receive different names or encoded bytes can lose their meaning.


**Section (fragment)** · `sec:interchange:area-fragment` If fragment claims fail, unsupported schema forms can enter algorithms whose guarantees require the assignable fragment.


**Section (inclusion)** · `sec:interchange:area-inclusion` If inclusion claims fail, incompatible theories can be mistaken for additive refinements.


**Section (labels)** · `sec:interchange:area-labels` If label claims fail, identifiers can be parsed ambiguously or accepted outside their canonical language.


**Section (lex)** · `sec:interchange:area-lex` If lexical claims fail, invalid input can be tokenized as a different valid schema or diagnostics can identify the wrong position.


**Section (parse)** · `sec:interchange:area-parse` If parsing claims fail, schema structure can change or adversarial nesting can cause repeated descent.


**Section (prefix)** · `sec:interchange:area-prefix` If prefix claims fail, incomplete bytes can select a reader prematurely or require more bytes than the declared bound.


**Section (print)** · `sec:interchange:area-print` If printing claims fail, schema text can change meaning or fail to reach its canonical fixed point.


**Section (properties)** · `sec:interchange:area-properties` If sampled metatheorem claims fail, canonical names, bounded routing or compatibility invariants have a concrete counterexample.


**Section (regexp)** · `sec:interchange:area-regexp` If regular-expression claims fail, supported patterns can decide the wrong match or exceed the declared work limit.


**Section (registry)** · `sec:interchange:area-registry` If registry claims fail, invalid or ambiguous theory histories can be admitted as supported versions.


**Section (resolve)** · `sec:interchange:area-resolve` If resolution claims fail, names and generic parameters can bind outside their declared scope.


**Section (restraint)** · `sec:interchange:area-restraint` If restraint claims fail, an implicit schema reach can admit forbidden values.


**Section (satisfaction)** · `sec:interchange:area-satisfaction` If satisfaction claims fail, a document can receive the wrong schema-conformance verdict.


**Section (theories)** · `sec:interchange:area-theories` If theory claims fail, registered schema identity and validation can diverge.


**Section (vectors)** · `sec:interchange:area-vectors` If vector claims fail, interchange behavior disagrees with the independent named conformance cases.


**Section (versions)** · `sec:interchange:area-versions` If version claims fail, edition ordering and compatibility can select an unsupported schema.

**Amendment (Bounded transport evidence)** · `amend:interchange:transport-evidence` The separate `Value::from_transport_bytes` entry implements (`[ROOT-rule:api:message-decoding]`) through the same private grammar walk as the canonical entries. Its finite caller declarations have no deployment defaults; the operational API limits remain pending. Allowed outer variants and unchanged embedded bytes have (`claim:encoding:transport-variants-preserve-values`); malformed and unsupported inputs have paired controls in (`claim:encoding:transport-refusals-retain-valid-controls`). Transport buffers grow geometrically, capped by the declared count for definite containers; relocation work and the full replacement capacity are charged before each reservation. Actual decoder reservation calls remain observable on refusal in (`claim:encoding:transport-limits-precede-reservations`), and (`claim:encoding:strict-entry-selects-strict-policy`) names the strict policy seam. The unchanged canonical corpus remains required. This scopes (`[ROOT-verif:xchg:bounded-transport]`) to transient values; it establishes neither a served API nor membership of a carried document.
