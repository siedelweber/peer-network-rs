**Record (Toolchain and build profile)** · `rec:toolchain:decision` Status: accepted. Scope: The workspace compiler channel, compiler minimum and release optimisation policy. Depends on: (`rec:lint:decision`). Does not establish: Tracking nightly establishes no reproducible compiler pin or measured dev and test optimisation policy.

## Toolchain and build profile · `sec:toolchain:record`

**Decision (Compiler)** · `dec:toolchain:compiler` The workspace tracks the undated nightly channel with rustfmt and clippy. Every workspace build, test and gate runs on compute nodes whose shared toolchain root carries the current nightly; worker accounts cannot install a toolchain there. The toolchain file therefore names the channel the nodes carry rather than a date they may not carry. Since no pin records the compiler, the gate log is the record of the versions that checked each commit.

**Decision (Minimum compiler)** · `dec:toolchain:minimum` The workspace and its first-party members declare no minimum compiler version. Tracking nightly would make a minimum a claim nothing checks, and no downstream consumer builds this workspace on an older compiler.

**Decision (Release profile)** · `dec:toolchain:release` Releases use thin LTO and 1 codegen unit. Thin LTO provides most of full LTO's cross-crate inlining at a fraction of its link time, and one codegen unit lets the optimiser see each crate whole. Dev and test profiles retain Cargo defaults so gate builds keep their incremental speed; changing their optimisation levels requires later measurement.

**Gate (Verification)** · `gate:toolchain:verification` The toolchain step requires the exactly undated nightly channel, both declared components and answering compiler, Cargo, Clippy and formatter commands, and logs rustc -vV, cargo -V, cargo clippy -V and rustfmt -V. The build-policy step refuses minimum compiler declarations in the workspace and first-party members, requires the release profile, and refuses dev or test overrides. The discipline-tests step witnesses rejection of dated nightly, stable releases and missing components.
