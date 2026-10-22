# Documents · `guide:documents:overview`

**Setup (Scope)** · `setup:documents:scope` The documents package projects inputs, renders templates and checks that the committed outputs and document census agree. Its tests state their claims beside the code that witnesses them. The rendering policy and helper restrictions are fixed by [record 003](../../adr/003-templated-documentation.md).

**Rule (Registry views)** · `rule:documents:registry` The registry record and enforced relation share the kinds dataset and the fixed-point check under [record 003](../../adr/003-templated-documentation.md).

**Rule (Record front matter)** · `rule:documents:records` Each record selects its own path in org.peer-network.records.index and includes fragments/record-front-matter.j2 from docs/fragments/. That shared fragment renders status, scope, dependency citations and the non-establishment sentence from the row; fragments have no independent output path.

## Claim areas · `sec:documents:areas`

**Section (envelope)** · `sec:documents:area-envelope` If envelope claims fail, a malformed or incompatible structured file can be treated as valid data before its identity is established.

**Section (render)** · `sec:documents:area-render` If rendering claims fail, committed documents can silently drift from their inputs or conceal unsupported premises.

**Section (cli)** · `sec:documents:area-cli` If command contract claims fail, machine callers cannot distinguish results from diagnostics or rely on process status before using an output.
