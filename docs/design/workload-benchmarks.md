# Structural workload measurements · `rec:design:workload-benchmark-series`

**Convention (Workload inputs)** · `conv:harness:workload-benchmark-inputs` Component curves measure a declared deterministic recipe through public constructors and validators. Correctness is checked before sampling and after the timed series; input construction is excluded, while allocations made by the operation and destruction of its returned owned output remain timed. Consuming marker operations receive a fresh input clone outside each timed iteration. Fixture proof equality measures structural evidence handling, not cryptographic verification or chain finality. A refused, unsupported or incomplete point remains an explicitly typed result and cannot be fitted as successful throughput. Source, configuration, dimensions, limits, setup, raw samples and resource scope accompany every measurement. Each campaign states its resource scopes. The earlier campaign has container cgroup readings only; the all-components campaign additionally records node-wide pressure, load and busy cores from proc, separately from its container cgroup. Waited process accounting gives own CPU. Neither scope attributes work to another login. Every float in the authored carrier uses exponent-free decimal notation, expanding exactly the digits of its shortest round-trip representation. The writer preserves the parsed value, including signed zero; the reader refuses other spellings. Every retained value parses back identically to the campaign raw result, as checked by the round-trip witness. The generated dataset carries those same values in the documents serializer's canonical form; its spelling need not match the authored input. The input rule prevents ambiguous digit runs without rounding evidence or changing the serializer. These curves declare no host workload, production API limit or capacity.

**Record (Sampling contract)** · `rec:workload:sampling` Full campaigns use 10 samples, 100 ms warm-up, 1 000 ms measurement targets and 1 000 statistical resamples, with flat iteration scheduling. The profile is gate and the deterministic seed is 0. These are bounded sampling settings, not elapsed deadlines: a slow operation completes and retains its measured cost. A serialized pilot precedes a full series. The existing foundation smoke retains its settings; the extra smoke points are declared in the grid carrier. Full campaigns run serially at idle priority on a recorded allowed CPU with a separate build target. Timing is nonverdict under (`rule:devperf:nonverdict`). The dataset names each package-owned construction control. Result association is checked by (`claim:harness:workload-result-binding`).

## Declared grids · `sec:workload:grids`

| Grid | Package and target | Sizes | Variants | Timed | Excluded |
| --- | --- | --- | --- | --- | --- |
| B1 | pn-records / workload-records | 16, 64, 256, 1 024 complete acts | parallel, mixed | validate_history, including returned owned output destruction | raw construction and correctness checks |
| B13 | pn-records / workload-records | 1, 4, 16, 64 markers including initial marker | list, commitment | validate_marker_history followed by recognize_markers, including returned owned output destruction | raw construction, burn and policy binding, correctness, per-iteration input clone |
| B14 | pn-interchange / workload-transport | 256, 1 024, 4 096, 16 384 payload bytes | strict, chunked | strict or transport decoding and owned output destruction; transport counters include the decoder's allocations | payload and canonical/chunked encoding construction, correctness |
| B2 | pn-graph / workload-graph | 8, 32, 128, 512 complete acts | 0, 1, 2 | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B4 | pn-graph / workload-graph | 2, 4, 8, 16 Actors | sparse-exact, sparse-enclosed, dense-exact, dense-enclosed | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B16 | pn-graph / workload-graph | 4, 16, 64, 256 complete acts | alternating | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B3 | pn-epoch / workload-epoch | 2, 4, 8, 16 Actors | ring, dense | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B3 | pn-epoch / workload-epoch | 8, 32, 128, 512 complete acts | parallel, mixed | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B5 | pn-epoch / workload-epoch | 8, 16 precision bits | equal, late, limited | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B6 | pn-epoch / workload-epoch | 2, 4, 8, 16 Actors | ring, dense | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B7 | pn-epoch / workload-epoch | 2, 4, 8, 16 Actors | ring, dense | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B8 | pn-epoch / workload-epoch | 4, 16, 64 complete acts | pass, own, individual, policy | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B9 | pn-epoch / workload-epoch | 1, 2, 4, 8 boundary-search sets | serial | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |
| B10 | pn-epoch / workload-epoch | 1, 2, 4, 8 refinement cap | rational, ridge | Public component operation and owned output destruction; B6 includes mandatory replay; B7 replays the exact returned B6 record, never an unrelated case. | Construction, validation, oracle/counter checks and fresh input/context setup; rejected points have no fitted samples. |

**Record (Act history curve)** · `rec:workload:act-history` The act grid measures complete-history structural validation with distinct act identities and fixed Actor names over a shared endpoint. Its mixed variant alternates complete binary and paired fixture families. It does not execute the epoch compiler's family formation or establish authentication validity. The recipe and sizes live in the workload dataset; no paper wall bound is inferred for the complete validator.

**Record (Marker history curve)** · `rec:workload:marker-history` The marker grid measures validation and recognition together, with policy and burn binding prepared before timing. The initial marker has an empty accepted set; successors repeat a complete accepted singleton with valid lineage and predecessor links. List and commitment representations are separate curves. The commitment fixture checks the complete opening bytes; no real settlement latency is represented by its synthetic positions.

**Record (Transport byte curve)** · `rec:workload:codec-bytes` The byte grid compares strict canonical byte strings with allowed indefinite transport strings over equal payloads. Empty chunks remain legal and are included. Each transport operation receives explicit input, allocation, item, depth, nesting and work limits from the experiment recipe. The decoder's reservation counter explains requested allocation work; it is not a general allocator or peak-memory measurement.

## Campaign evidence · `sec:workload:campaigns`

The earlier structural campaign records its public base with the measured implementation patch applied. The all-components campaign records an exact clean public checkout: its source base and measured-series commit are the same, and no patch is applied. Each measured-series entry uses the existing ancestor-patch reader to recompute the public commit's stable patch-id. The later campaign retains all 118 points and does not replace the earlier records and interchange measurements. It is the first graph and epoch campaign and the second records and interchange campaign; no workload or capacity declaration follows from these component curves.

| Campaign or point | Outcome | Wall seconds | Own CPU seconds | Source and scope |
| --- | --- | --- | --- | --- |
| kranich-structural-pilot | passed | 1.880 480 678 999 447 3 | 1.698 951 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-structural-full | passed | 28.039 887 226 001 156 | 27.872 506 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-parallel-16 | passed | 1.213 378 984 999 508 2 | 1.209 001 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-parallel-64 | passed | 1.218 967 405 000 512 4 | 1.214 535 000 000 000 1 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-parallel-256 | passed | 1.139 316 311 000 584 4 | 1.133 876 999 999 999 8 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-parallel-1024 | passed | 1.090 637 871 999 206 3 | 1.085 475 999 999 999 9 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-mixed-16 | passed | 1.109 403 348 000 341 8 | 1.101 737 999 999 999 9 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-mixed-64 | passed | 1.117 519 729 999 912 7 | 1.112 047 000 000 000 2 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-mixed-256 | passed | 1.154 530 989 999 33 | 1.146 812 999 999 999 9 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-acts-mixed-1024 | passed | 1.164 735 529 999 234 1 | 1.157 464 999 999 999 5 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-list-1 | passed | 1.207 639 895 001 193 5 | 1.202 440 999 999 998 3 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-list-4 | passed | 1.127 803 266 999 762 9 | 1.121 751 000 000 001 7 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-list-16 | passed | 1.124 574 917 999 780 2 | 1.116 841 000 000 000 6 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-list-64 | passed | 1.129 161 983 999 438 2 | 1.118 567 999 999 999 8 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-commitment-1 | passed | 1.121 079 062 999 342 6 | 1.112 099 999 999 998 5 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-commitment-4 | passed | 1.174 778 350 999 986 3 | 1.166 051 000 000 000 8 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-commitment-16 | passed | 1.143 313 243 999 728 | 1.134 343 999 999 998 5 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-markers-commitment-64 | passed | 1.154 643 950 001 627 7 | 1.146 648 000 000 001 9 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-strict-256 | passed | 1.190 993 595 000 691 1 | 1.185 842 000 000 001 2 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-strict-1024 | passed | 1.190 778 225 000 031 | 1.186 598 999 999 998 2 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-strict-4096 | passed | 1.181 912 484 998 974 8 | 1.159 729 000 000 001 8 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-strict-16384 | passed | 1.150 679 808 000 859 3 | 1.144 918 000 000 000 3 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-chunked-256 | passed | 1.138 069 831 999 018 8 | 1.133 298 000 000 001 7 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-chunked-1024 | passed | 1.100 909 355 998 737 7 | 1.097 055 999 999 999 6 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-chunked-4096 | passed | 1.110 484 279 999 582 2 | 1.106 520 999 999 999 4 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-full-bytes-chunked-16384 | passed | 1.123 355 197 998 535 | 1.119 397 000 000 000 2 | Container cgroup samples only; waited runner/process accounting is own CPU. Component evidence, no capacity or other-logins attribution. |
| kranich-all-components-2 | passed | 182.578 214 645 385 74 | 179.223 596 000 000 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-parallel-16 | passed | 1.030 717 619 996 721 6 | 1.026 138 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-parallel-64 | passed | 1.230 636 275 002 325 4 | 1.223 256 000 000 000 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-parallel-256 | passed | 1.125 501 457 001 519 2 | 1.118 769 999 999 999 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-parallel-1024 | passed | 1.167 463 788 999 157 3 | 1.161 968 000 000 000 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-mixed-16 | passed | 1.182 279 920 998 553 3 | 1.101 422 999 999 999 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-mixed-64 | passed | 1.184 713 737 999 118 2 | 1.175 198 000 000 000 9 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-mixed-256 | passed | 1.072 281 012 999 155 8 | 1.059 524 999 999 999 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-acts-mixed-1024 | passed | 1.196 708 373 998 262 7 | 1.183 569 999 999 997 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-list-1 | passed | 1.113 437 632 000 568 6 | 1.100 666 000 000 000 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-list-4 | passed | 1.189 806 160 000 444 | 1.136 721 999 999 999 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-list-16 | passed | 1.107 642 388 000 385 8 | 1.100 338 999 999 999 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-list-64 | passed | 1.116 631 458 000 483 7 | 1.108 813 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-commitment-1 | passed | 1.083 233 519 002 533 3 | 1.076 227 000 000 000 3 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-commitment-4 | passed | 1.112 688 905 002 869 4 | 1.097 610 999 999 998 3 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-commitment-16 | passed | 1.269 010 280 000 657 | 1.238 316 999 999 999 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-markers-commitment-64 | passed | 1.147 949 493 999 476 5 | 1.140 186 000 000 000 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-strict-256 | passed | 1.196 826 923 998 742 1 | 1.184 858 999 999 996 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-strict-1024 | passed | 1.188 214 923 000 487 | 1.178 712 000 000 001 3 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-strict-4096 | passed | 1.129 061 280 000 314 6 | 1.123 002 999 999 998 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-strict-16384 | passed | 1.148 521 144 001 279 | 1.142 513 000 000 000 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-chunked-256 | passed | 1.181 711 227 000 050 7 | 1.166 039 000 000 001 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-chunked-1024 | passed | 0.900 959 586 000 681 2 | 0.861 630 999 999 996 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-chunked-4096 | passed | 1.168 997 699 001 920 4 | 1.162 619 000 000 001 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-bytes-chunked-16384 | passed | 1.198 660 289 999 679 7 | 1.187 059 999 999 996 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-0-8 | passed | 1.154 214 727 997 896 3 | 1.146 814 999 999 998 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-0-32 | passed | 1.278 860 263 999 377 | 1.258 053 000 000 003 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-0-128 | passed | 0.881 565 744 002 728 | 0.866 561 999 999 997 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-0-512 | passed | 1.180 737 193 000 823 | 1.164 175 000 000 001 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-1-8 | passed | 1.202 430 772 998 923 2 | 1.192 989 999 999 996 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-1-32 | passed | 1.149 593 990 001 449 1 | 1.141 494 000 000 001 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-1-128 | passed | 1.149 438 541 997 369 6 | 1.140 200 000 000 008 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-1-512 | passed | 2.136 145 136 999 403 | 2.114 441 000 000 002 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-2-8 | passed | 0.890 014 623 000 752 2 | 0.881 600 000 000 002 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-2-32 | passed | 1.409 601 720 999 489 8 | 1.396 913 000 000 002 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-2-128 | passed | 1.167 975 575 997 843 4 | 1.155 230 000 000 004 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-partition-2-512 | passed | 1.169 716 281 001 456 | 1.161 495 999 999 997 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-exact-2 | passed | 1.183 141 134 999 459 6 | 1.162 037 000 000 004 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-exact-4 | passed | 1.136 376 729 999 028 6 | 1.129 803 999 999 999 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-exact-8 | passed | 1.257 585 408 999 148 | 1.245 239 000 000 002 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-exact-16 | passed | 0.742 555 041 997 548 | 0.737 944 999 999 998 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-enclosed-2 | passed | 1.192 991 059 000 633 | 1.182 348 000 000 002 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-enclosed-4 | passed | 1.181 942 596 002 045 3 | 1.174 780 000 000 003 3 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-enclosed-8 | passed | 1.174 457 582 001 196 | 1.163 819 999 999 995 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-sparse-enclosed-16 | passed | 1.192 201 215 999 375 6 | 1.181 433 999 999 997 9 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-exact-2 | passed | 1.236 497 420 999 512 5 | 1.225 806 999 999 998 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-exact-4 | passed | 1.415 894 836 998 632 | 1.375 213 000 000 003 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-exact-8 | passed | 1.129 301 473 996 747 5 | 1.089 416 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-exact-16 | refused | 0.015 917 933 000 309 86 | 0.015 169 999 999 993 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-enclosed-2 | passed | 1.212 596 100 998 780 5 | 1.177 312 000 000 004 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-enclosed-4 | passed | 1.128 479 472 001 345 1 | 1.115 014 999 999 998 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-enclosed-8 | passed | 1.231 178 999 998 519 4 | 1.190 835 000 000 002 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-transport-dense-enclosed-16 | refused | 0.017 293 750 999 670 01 | 0.016 521 000 000 000 896 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-title-alternating-4 | passed | 1.063 771 001 001 441 6 | 0.988 452 999 999 995 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-title-alternating-16 | passed | 1.113 202 135 999 017 6 | 1.095 100 999 999 997 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-title-alternating-64 | passed | 0.994 311 869 999 364 7 | 0.983 282 000 000 008 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-title-alternating-256 | passed | 1.740 007 831 002 003 5 | 1.724 873 999 999 994 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-ring-2 | passed | 1.565 263 443 997 537 3 | 1.534 298 000 000 001 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-ring-4 | passed | 1.223 975 698 998 401 6 | 1.179 489 000 000 000 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-ring-8 | passed | 1.148 488 332 000 852 | 1.108 431 999 999 991 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-ring-16 | passed | 1.236 092 089 999 147 | 1.223 941 000 000 006 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-dense-2 | passed | 1.114 092 355 001 048 4 | 1.104 501 999 999 998 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-dense-4 | passed | 1.125 381 934 998 586 | 1.107 287 999 999 997 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-dense-8 | passed | 0.796 743 808 998 144 2 | 0.787 725 999 999 982 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-actors-dense-16 | passed | 2.799 320 573 998 557 | 2.555 873 999 999 996 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-parallel-8 | passed | 1.230 446 583 998 855 2 | 1.217 651 999 999 997 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-parallel-32 | passed | 1.191 135 082 000 983 | 1.175 576 999 999 988 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-parallel-128 | passed | 1.399 023 887 999 646 8 | 1.376 049 999 999 995 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-parallel-512 | passed | 1.563 698 575 002 490 5 | 1.554 529 000 000 003 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-mixed-8 | passed | 1.315 644 414 000 416 9 | 1.297 752 000 000 013 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-mixed-32 | passed | 1.245 723 999 996 698 7 | 1.237 553 000 000 007 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-mixed-128 | passed | 2.320 580 422 998 318 7 | 2.298 627 999 999 995 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-compile-acts-mixed-512 | passed | 3.293 131 387 999 892 5 | 3.257 200 000 000 013 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-equal-8 | passed | 1.167 508 591 002 842 9 | 1.154 927 999 999 995 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-equal-16 | passed | 1.187 712 552 000 448 3 | 1.174 158 999 999 998 8 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-late-8 | passed | 2.081 206 270 002 44 | 2.064 832 999 999 993 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-late-16 | passed | 2.895 258 702 999 854 | 2.872 361 000 000 000 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-limited-8 | refused | 0.007 297 756 001 207 745 | 0.006 945 000 000 012 635 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-fence-limited-16 | refused | 0.007 146 003 998 059 314 | 0.006 791 999 999 995 912 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-ring-2 | passed | 5.430 093 866 001 698 | 5.400 723 999 999 993 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-ring-4 | refused | 0.650 033 522 000 74 | 0.643 783 999 999 994 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-ring-8 | refused | 0.643 848 196 003 091 3 | 0.639 954 999 999 991 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-ring-16 | refused | 0.778 083 553 999 749 7 | 0.767 677 000 000 009 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-dense-2 | passed | 8.302 159 868 999 297 | 8.155 706 000 000 002 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-dense-4 | refused | 0.680 835 398 001 363 5 | 0.671 650 999 999 988 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-dense-8 | refused | 0.683 566 054 001 858 | 0.678 029 000 000 008 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-solve-dense-16 | refused | 0.721 117 270 000 831 9 | 0.715 432 000 000 002 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-ring-2 | passed | 2.447 633 881 001 820 6 | 2.426 944 999 999 995 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-ring-4 | refused | 0.362 056 428 999 494 53 | 0.359 534 999 999 995 05 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-ring-8 | refused | 0.372 101 123 000 902 6 | 0.369 576 000 000 003 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-ring-16 | refused | 0.376 225 119 998 707 67 | 0.373 836 999 999 997 53 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-dense-2 | passed | 2.522 850 113 997 265 | 2.502 413 000 000 002 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-dense-4 | refused | 0.371 397 828 999 761 26 | 0.368 862 000 000 010 24 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-dense-8 | refused | 0.377 918 966 998 549 9 | 0.375 711 000 000 009 45 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-replay-dense-16 | refused | 0.413 140 548 000 228 6 | 0.410 993 000 000 003 5 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-pass-4 | passed | 1.418 746 871 997 427 7 | 1.406 926 000 000 002 1 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-pass-16 | passed | 1.389 433 371 998 166 | 1.381 828 000 000 012 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-pass-64 | passed | 1.455 181 219 000 223 8 | 1.444 442 000 000 002 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-own-4 | refused | 0.005 062 505 999 376 299 | 0.004 649 000 000 002 346 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-own-16 | refused | 0.005 777 149 002 824 444 | 0.005 378 999 999 998 246 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-own-64 | refused | 0.008 978 478 999 779 327 | 0.008 471 999 999 996 482 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-individual-4 | refused | 0.326 851 589 001 307 73 | 0.324 269 000 000 003 9 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-individual-16 | refused | 0.325 326 393 998 693 7 | 0.322 664 999 999 992 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-individual-64 | refused | 0.330 677 655 001 636 6 | 0.327 611 000 000 001 2 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-policy-4 | refused | 0.214 638 607 001 688 8 | 0.212 814 000 000 001 17 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-policy-16 | refused | 0.209 174 416 999 303 5 | 0.207 508 999 999 999 06 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-admit-policy-64 | refused | 0.220 522 153 998 899 74 | 0.218 739 000 000 003 57 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-trials-serial-1 | passed | 1.370 799 903 001 170 6 | 1.362 212 999 999 997 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-trials-serial-2 | passed | 3.510 463 793 998 497 | 3.379 203 000 000 021 3 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-trials-serial-4 | passed | 5.453 210 749 998 107 | 5.417 560 999 999 981 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-trials-serial-8 | passed | 12.299 865 469 001 816 | 12.130 265 000 000 01 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-rational-1 | refused | 2.756 817 839 002 906 | 2.660 586 000 000 003 4 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-rational-2 | refused | 2.856 987 757 000 752 | 2.771 576 999 999 995 7 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-rational-4 | refused | 3.037 025 631 998 403 7 | 2.936 983 000 000 003 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-rational-8 | refused | 3.069 229 435 001 034 3 | 2.994 103 000 000 007 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-ridge-1 | refused | 2.888 316 659 002 157 4 | 2.774 046 000 000 005 6 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-ridge-2 | passed | 5.155 154 480 999 045 | 4.982 764 000 000 011 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-ridge-4 | passed | 5.295 320 883 000 386 | 5.072 337 000 000 01 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| kranich-all-components-2-scalar-ridge-8 | passed | 5.370 919 963 999 768 | 5.193 663 000 000 006 | Component evidence only, no capacity declaration. node_scope=node-wide from proc; cgroup_scope=gate-cgroup from the campaign container; waited process CPU is own CPU. |
| Measured source | Public base | Public implementation commit and stable patch-id | Scheduling and machine |
| --- | --- | --- | --- |
| kranich-structural-pilot | `ad94eb24887ecbda0f34a95884ca99b7f6f504e9` | commit `7cc999af9e209ce9cda111a7db1554e3cb11232f`; stable patch-id `0a1f215440a4e8a6bdd8af10f12192b8e7463acb` | kranich; AMD Ryzen 9 5950X 16-Core Processor; SCHED_IDLE. |
| kranich-structural-full | `ad94eb24887ecbda0f34a95884ca99b7f6f504e9` | commit `7cc999af9e209ce9cda111a7db1554e3cb11232f`; stable patch-id `0a1f215440a4e8a6bdd8af10f12192b8e7463acb` | kranich; AMD Ryzen 9 5950X 16-Core Processor; SCHED_IDLE. |
| kranich-all-components-2 | `2afc7a89ce57783a2bc6928828ae0066fb19178e` | commit `2afc7a89ce57783a2bc6928828ae0066fb19178e`; stable patch-id `d943a78a85880844ee4cec32ef19abac7652bd6b` | kranich; AMD Ryzen 9 5950X 16-Core Processor; SCHED_IDLE. |

| Full point | Size | Mean ns | Mean confidence interval ns | Setup seconds | Outcome |
| --- | --- | --- | --- | --- | --- |
| acts-parallel-16 | 16 | 22 819.400 976 692 563 | 22 352.889 790 788 016 to 23 704.870 627 081 018 | 0.000 113 561 | passed |
| acts-parallel-64 | 64 | 93 553.803 727 272 74 | 91 773.335 713 636 35 to 95 437.161 647 727 28 | 0.000 275 179 | passed |
| acts-parallel-256 | 256 | 462 756.211 363 636 3 | 456 634.806 715 909 1 to 472 775.467 568 181 8 | 0.001 157 804 | passed |
| acts-parallel-1024 | 1 024 | 1 937 154.610 204 081 5 | 1 915 013.150 306 122 6 to 1 957 126.815 408 163 | 0.004 426 428 | passed |
| acts-mixed-16 | 16 | 27 536.304 510 022 27 | 27 293.963 290 645 88 to 27 818.251 877 783 97 | 0.000 120 654 | passed |
| acts-mixed-64 | 64 | 119 080.830 649 038 46 | 118 028.282 770 432 69 to 120 011.349 110 576 9 | 0.000 347 724 | passed |
| acts-mixed-256 | 256 | 541 325.261 497 326 3 | 538 908.943 890 374 3 to 543 702.778 729 946 6 | 0.001 285 381 | passed |
| acts-mixed-1024 | 1 024 | 2 243 481.659 999 999 7 | 2 234 578.901 444 444 to 2 253 373.127 944 444 | 0.005 794 712 | passed |
| markers-list-1 | 1 | 2 704.256 659 066 727 5 | 2 684.426 311 749 506 to 2 726.805 750 569 996 | 0.000 081 341 | passed |
| markers-list-4 | 4 | 7 480.698 823 430 541 | 7 423.575 809 942 012 to 7 537.148 704 933 187 | 0.000 166 548 | passed |
| markers-list-16 | 16 | 26 857.645 635 759 585 | 26 759.226 000 453 03 to 26 966.749 389 157 354 | 0.000 168 652 | passed |
| markers-list-64 | 64 | 99 825.913 444 444 44 | 98 874.368 183 333 34 to 100 761.374 6 | 0.000 438 312 | passed |
| markers-commitment-1 | 1 | 2 852.680 651 076 012 | 2 826.770 652 121 465 4 to 2 888.980 405 877 054 6 | 0.000 088 514 | passed |
| markers-commitment-4 | 4 | 8 654.724 597 083 652 | 8 597.764 277 388 718 to 8 709.964 196 325 785 | 0.000 117 898 | passed |
| markers-commitment-16 | 16 | 30 910.890 886 524 827 | 30 677.309 787 234 04 to 31 134.586 574 468 085 | 0.000 187 027 | passed |
| markers-commitment-64 | 64 | 114 636.657 290 322 59 | 110 121.611 980 645 16 to 120 909.984 064 516 15 | 0.000 478 887 | passed |
| bytes-strict-256 | 256 | 70.716 973 150 464 1 | 69.932 077 103 073 91 to 71.620 953 700 491 8 | 0.000 021 66 | passed |
| bytes-strict-1024 | 1 024 | 81.572 139 258 898 91 | 81.292 231 872 531 63 to 81.828 393 025 453 35 | 0.000 014 467 | passed |
| bytes-strict-4096 | 4 096 | 126.676 790 287 999 78 | 126.480 834 327 409 38 to 126.898 539 413 887 86 | 0.000 018 725 | passed |
| bytes-strict-16384 | 16 384 | 271.682 882 422 867 | 269.913 684 578 808 04 to 274.063 535 135 354 2 | 0.000 051 044 | passed |
| bytes-chunked-256 | 256 | 280.178 262 612 250 25 | 276.276 068 725 997 16 to 284.103 919 555 064 07 | 0.000 020 107 | passed |
| bytes-chunked-1024 | 1 024 | 765.827 743 972 710 1 | 762.938 290 155 042 3 to 768.163 612 647 705 | 0.000 013 946 | passed |
| bytes-chunked-4096 | 4 096 | 2 284.101 089 964 148 7 | 2 265.023 649 214 408 to 2 307.508 475 072 784 | 0.000 027 401 | passed |
| bytes-chunked-16384 | 16 384 | 8 094.877 917 385 235 | 8 072.291 231 214 585 to 8 117.959 844 994 662 5 | 0.000 080 018 | passed |
| acts-parallel-16 | 16 | 23 316.174 261 922 784 | 22 903.261 718 395 155 to 23 800.259 695 937 424 | 0.000 129 4 | passed |
| acts-parallel-64 | 64 | 97 752.555 345 316 96 | 96 414.609 058 656 57 to 99 100.010 612 582 77 | 0.000 280 579 | passed |
| acts-parallel-256 | 256 | 442 350.719 298 245 56 | 441 297.342 817 982 5 to 443 494.384 100 877 16 | 0.001 106 78 | passed |
| acts-parallel-1024 | 1 024 | 1 922 963.425 925 926 | 1 917 885.493 518 518 3 to 1 926 984.626 435 184 9 | 0.004 255 792 | passed |
| acts-mixed-16 | 16 | 27 686.556 482 777 93 | 27 496.914 359 423 135 to 27 918.135 090 310 84 | 0.000 116 506 | passed |
| acts-mixed-64 | 64 | 128 219.074 150 485 42 | 120 442.278 977 548 56 to 137 014.013 637 742 73 | 0.000 341 903 | passed |
| acts-mixed-256 | 256 | 575 124.307 692 307 6 | 562 461.077 580 128 3 to 586 364.223 124 999 9 | 0.001 449 024 | passed |
| acts-mixed-1024 | 1 024 | 2 487 075.568 292 682 5 | 2 472 604.128 414 633 7 to 2 501 597.210 548 78 | 0.005 705 748 | passed |
| markers-list-1 | 1 | 4 850.956 319 210 4 | 4 199.957 782 709 436 to 5 362.860 638 992 538 | 0.000 194 86 | passed |
| markers-list-4 | 4 | 7 996.031 163 163 521 | 7 953.304 501 469 54 to 8 035.231 663 697 898 | 0.000 114 702 | passed |
| markers-list-16 | 16 | 28 005.100 871 811 435 | 27 832.218 782 692 926 to 28 170.518 182 918 953 | 0.000 186 124 | passed |
| markers-list-64 | 64 | 99 885.828 587 570 62 | 98 764.780 087 570 62 to 101 012.304 375 706 23 | 0.000 420 568 | passed |
| markers-commitment-1 | 1 | 2 906.240 866 947 209 7 | 2 859.659 440 709 569 to 2 958.468 629 785 487 | 0.000 099 805 | passed |
| markers-commitment-4 | 4 | 9 230.126 727 334 007 | 8 648.919 677 564 318 to 10 094.861 259 689 924 | 0.000 111 857 | passed |
| markers-commitment-16 | 16 | 40 462.109 178 947 36 | 35 560.789 550 526 315 to 45 764.769 968 421 06 | 0.000 180 284 | passed |
| markers-commitment-64 | 64 | 122 982.170 803 949 24 | 122 151.801 646 685 48 to 123 747.843 998 589 55 | 0.000 490 619 | passed |
| bytes-strict-256 | 256 | 78.754 973 988 754 24 | 77.930 698 998 412 75 to 79.654 595 395 015 08 | 0.000 022 321 | passed |
| bytes-strict-1024 | 1 024 | 87.067 729 996 352 71 | 86.591 151 955 207 8 to 87.565 251 610 886 28 | 0.000 012 994 | passed |
| bytes-strict-4096 | 4 096 | 130.690 350 305 563 73 | 130.150 659 213 666 78 to 131.175 782 614 655 9 | 0.000 019 457 | passed |
| bytes-strict-16384 | 16 384 | 286.708 576 119 006 8 | 285.582 989 430 239 8 to 287.634 503 392 940 64 | 0.000 051 796 | passed |
| bytes-chunked-256 | 256 | 304.474 994 801 695 97 | 303.106 642 061 361 1 to 305.659 634 687 303 2 | 0.000 014 638 | passed |
| bytes-chunked-1024 | 1 024 | 819.668 210 044 075 7 | 814.137 692 885 989 to 824.628 209 664 111 8 | 0.000 024 856 | passed |
| bytes-chunked-4096 | 4 096 | 2 581.088 107 645 640 3 | 2 570.737 333 683 337 to 2 590.284 872 443 027 3 | 0.000 029 545 | passed |
| bytes-chunked-16384 | 16 384 | 9 635.464 989 382 328 | 9 288.807 265 257 132 to 10 189.609 621 226 107 | 0.000 088 043 | passed |
| partition-0-8 | 8 | 9 284.602 084 108 67 | 9 230.516 375 372 163 to 9 330.591 343 273 167 | 0.000 164 295 | passed |
| partition-0-32 | 32 | 63 872.584 716 877 41 | 57 586.732 747 388 676 to 72 488.744 303 188 56 | 0.000 469 92 | passed |
| partition-0-128 | 128 | 643 635.672 268 907 5 | 549 309.039 054 622 to 741 385.528 907 563 | 0.002 217 788 | passed |
| partition-0-512 | 512 | 7 297 302.725 | 6 937 472.161 250 002 to 7 774 812.367 083 334 | 0.022 170 904 | passed |
| partition-1-8 | 8 | 15 624.915 062 943 135 | 15 321.741 647 735 495 to 16 162.134 115 540 443 | 0.000 180 324 | passed |
| partition-1-32 | 32 | 206 383.967 857 142 85 | 198 819.172 321 428 54 to 220 254.192 504 960 3 | 0.001 597 429 | passed |
| partition-1-128 | 128 | 3 203 757.503 225 806 | 3 181 385.886 290 322 5 to 3 227 258.796 612 903 5 | 0.041 097 17 | passed |
| partition-1-512 | 512 | 58 273 459.2 | 57 024 618.555 to 59 874 350.635 000 005 | 0.586 340 385 | passed |
| partition-2-8 | 8 | 11 013.400 947 867 3 | 10 761.848 434 582 796 to 11 361.073 062 616 688 | 0.000 319 992 | passed |
| partition-2-32 | 32 | 115 388.495 610 687 02 | 100 127.945 634 542 03 to 133 945.205 560 591 57 | 0.000 625 86 | passed |
| partition-2-128 | 128 | 1 208 388.424 096 385 5 | 1 200 311.720 361 446 to 1 216 940.727 740 963 7 | 0.003 585 471 | passed |
| partition-2-512 | 512 | 18 815 699.34 | 18 645 212.601 5 to 18 997 335.756 499 995 | 0.036 067 844 | passed |
| transport-sparse-exact-2 | 2 | 40 610.058 059 142 015 | 40 454.589 519 991 66 to 40 755.192 674 927 11 | 0.000 239 634 | passed |
| transport-sparse-exact-4 | 4 | 76 966.290 982 286 65 | 76 037.762 743 558 76 to 77 901.676 437 198 05 | 0.000 419 406 | passed |
| transport-sparse-exact-8 | 8 | 172 713.702 24 | 156 736.898 260 000 02 to 199 744.606 231 999 96 | 0.000 752 063 | passed |
| transport-sparse-exact-16 | 16 | 322 480.995 081 967 27 | 319 685.093 756 830 6 to 324 848.022 855 191 26 | 0.002 352 387 | passed |
| transport-sparse-enclosed-2 | 2 | 91 402.585 897 435 9 | 90 425.517 825 091 58 to 92 553.871 817 765 57 | 0.000 243 982 | passed |
| transport-sparse-enclosed-4 | 4 | 175 391.803 174 603 18 | 174 544.392 270 723 12 to 176 246.536 331 569 66 | 0.000 411 793 | passed |
| transport-sparse-enclosed-8 | 8 | 346 903.560 211 267 6 | 343 693.878 750 000 03 to 350 852.423 045 774 7 | 0.000 783 601 | passed |
| transport-sparse-enclosed-16 | 16 | 671 645.381 333 333 3 | 665 835.640 633 333 5 to 677 724.213 333 333 3 | 0.001 422 675 | passed |
| transport-dense-exact-2 | 2 | 42 932.901 072 607 26 | 40 342.477 882 632 01 to 46 060.403 294 141 914 | 0.000 231 629 | passed |
| transport-dense-exact-4 | 4 | 184 329.596 279 761 93 | 153 260.423 117 559 52 to 223 330.823 005 952 38 | 0.000 656 546 | passed |
| transport-dense-exact-8 | 8 | 706 944.783 593 75 | 579 956.508 378 906 3 to 861 923.603 593 749 9 | 0.002 457 873 | passed |
| transport-dense-exact-16 | 16 | unavailable: refused | not fitted | 0.012 545 476 | refused |
| transport-dense-enclosed-2 | 2 | 176 297.877 701 543 74 | 171 761.145 072 898 8 to 181 234.270 197 255 57 | 0.000 407 084 | passed |
| transport-dense-enclosed-4 | 4 | 559 095.954 913 294 6 | 549 106.729 176 300 6 to 569 668.249 595 375 6 | 0.001 160 299 | passed |
| transport-dense-enclosed-8 | 8 | 2 284 974.995 652 173 6 | 2 137 651.917 880 434 5 to 2 435 501.727 336 956 7 | 0.004 326 623 | passed |
| transport-dense-enclosed-16 | 16 | unavailable: refused | not fitted | 0.013 904 333 | refused |
| title-alternating-4 | 4 | 36 556.183 305 853 26 | 35 139.866 820 898 6 to 37 828.309 200 329 764 | 0.000 449 042 | passed |
| title-alternating-16 | 16 | 440 966.842 222 222 24 | 431 140.303 166 666 65 to 451 076.875 222 222 24 | 0.001 247 511 | passed |
| title-alternating-64 | 64 | 4 789 777.756 25 | 4 068 703.544 687 5 to 5 541 526.906 562 501 | 0.009 334 739 | passed |
| title-alternating-256 | 256 | 66 554 697.5 | 66 056 535.015 to 67 066 460.57 | 0.071 758 379 | passed |
| compile-actors-ring-2 | 2 | 570 265.956 972 111 5 | 476 377.042 410 358 55 to 653 076.768 655 378 4 | 0.000 839 495 | passed |
| compile-actors-ring-4 | 4 | 1 270 453.379 268 292 6 | 1 219 136.624 756 097 6 to 1 331 986.209 878 048 9 | 0.002 725 989 | passed |
| compile-actors-ring-8 | 8 | 1 602 686.063 934 426 3 | 1 572 670.237 254 098 to 1 641 566.776 516 393 3 | 0.002 427 977 | passed |
| compile-actors-ring-16 | 16 | 5 452 732.638 888 89 | 5 313 955.049 722 223 to 5 587 919.278 472 222 | 0.007 501 925 | passed |
| compile-actors-dense-2 | 2 | 670 975.662 962 963 | 649 802.524 833 333 4 to 691 736.032 314 814 9 | 0.001 365 369 | passed |
| compile-actors-dense-4 | 4 | 2 641 797.649 999 999 4 | 2 311 540.748 382 352 8 to 3 023 887.281 911 764 3 | 0.003 925 691 | passed |
| compile-actors-dense-8 | 8 | 8 369 631.442 857 143 5 | 8 244 665.476 071 428 5 to 8 492 858.470 000 003 | 0.011 055 848 | passed |
| compile-actors-dense-16 | 16 | 76 090 151.633 333 34 | 66 947 544.162 499 994 to 82 976 985.589 999 99 | 0.041 594 991 | passed |
| compile-acts-parallel-8 | 8 | 752 315.099 253 731 3 | 747 423.750 429 104 3 to 755 954.146 268 656 7 | 0.001 262 939 | passed |
| compile-acts-parallel-32 | 32 | 1 334 877.801 388 888 9 | 1 328 561.473 055 555 5 to 1 340 844.494 236 111 2 | 0.003 282 921 | passed |
| compile-acts-parallel-128 | 128 | 4 423 402.492 307 691 | 4 004 354.513 942 308 to 4 927 973.264 615 383 | 0.006 013 869 | passed |
| compile-acts-parallel-512 | 512 | 14 172 494.485 714 287 | 14 073 612.356 785 713 to 14 249 210.998 928 57 | 0.021 295 052 | passed |
| compile-acts-mixed-8 | 8 | 834 861.629 545 454 6 | 770 467.554 204 545 3 to 912 505.328 465 909 1 | 0.001 317 2 | passed |
| compile-acts-mixed-32 | 32 | 2 698 974.936 842 105 | 2 685 716.869 671 052 3 to 2 710 938.175 986 842 | 0.003 575 773 | passed |
| compile-acts-mixed-128 | 128 | 20 382 212.022 222 225 | 20 051 813.641 388 893 to 20 739 430.681 666 67 | 0.012 897 529 | passed |
| compile-acts-mixed-512 | 512 | 86 001 162.15 | 83 252 953.851 250 01 to 88 772 274.932 5 | 0.095 099 34 | passed |
| fence-equal-8 | 8 | 18 406.012 035 010 94 | 18 032.572 768 508 388 to 18 924.664 344 456 596 | 0.000 000 111 | passed |
| fence-equal-16 | 16 | 17 946.057 501 297 804 | 17 452.575 918 411 487 to 18 487.124 862 432 946 | 0.000 000 1 | passed |
| fence-late-8 | 8 | 157 606 105.1 | 155 239 506.799 999 98 to 159 670 992.232 500 02 | 0.000 000 12 | passed |
| fence-late-16 | 16 | 219 753 625.4 | 218 367 023.71 to 221 742 274.012 5 | 0.000 000 121 | passed |
| fence-limited-8 | 8 | unavailable: refused | not fitted | 0.000 000 11 | refused |
| fence-limited-16 | 16 | unavailable: refused | not fitted | 0.000 000 101 | refused |
| solve-ring-2 | 2 | 357 356 827.6 | 354 050 512.837 5 to 360 404 179.887 500 05 | 0.001 310 216 | passed |
| solve-ring-4 | 4 | unavailable: refused | not fitted | 0.001 362 113 | refused |
| solve-ring-8 | 8 | unavailable: refused | not fitted | 0.002 257 912 | refused |
| solve-ring-16 | 16 | unavailable: refused | not fitted | 0.004 404 287 | refused |
| solve-dense-2 | 2 | 627 673 573.2 | 584 945 485.595 to 655 536 471.075 | 0.000 888 655 | passed |
| solve-dense-4 | 4 | unavailable: refused | not fitted | 0.002 764 56 | refused |
| solve-dense-8 | 8 | unavailable: refused | not fitted | 0.010 429 876 | refused |
| solve-dense-16 | 16 | unavailable: refused | not fitted | 0.044 388 779 | refused |
| replay-ring-2 | 2 | 132 436 334.0 | 131 596 210.350 000 01 to 133 076 113.58 | 0.000 967 081 | passed |
| replay-ring-4 | 4 | unavailable: refused | not fitted | 0.001 396 036 | refused |
| replay-ring-8 | 8 | unavailable: refused | not fitted | 0.002 322 822 | refused |
| replay-ring-16 | 16 | unavailable: refused | not fitted | 0.004 352 601 | refused |
| replay-dense-2 | 2 | 137 029 003.8 | 136 685 991.495 to 137 237 842.935 | 0.000 906 238 | passed |
| replay-dense-4 | 4 | unavailable: refused | not fitted | 0.002 728 403 | refused |
| replay-dense-8 | 8 | unavailable: refused | not fitted | 0.010 152 572 | refused |
| replay-dense-16 | 16 | unavailable: refused | not fitted | 0.042 564 581 | refused |
| admit-pass-4 | 4 | 105 727 479.4 | 105 136 290.687 5 to 106 663 194.307 5 | 0.000 000 4 | passed |
| admit-pass-16 | 16 | 102 567 391.8 | 102 286 840.377 5 to 102 899 742.265 | 0.000 000 351 | passed |
| admit-pass-64 | 64 | 105 216 308.8 | 104 672 125.630 000 01 to 105 696 929.68 | 0.000 000 471 | passed |
| admit-own-4 | 4 | unavailable: refused | not fitted | 0.000 000 421 | refused |
| admit-own-16 | 16 | unavailable: refused | not fitted | 0.000 000 361 | refused |
| admit-own-64 | 64 | unavailable: refused | not fitted | 0.000 000 431 | refused |
| admit-individual-4 | 4 | unavailable: refused | not fitted | 0.000 000 381 | refused |
| admit-individual-16 | 16 | unavailable: refused | not fitted | 0.000 000 4 | refused |
| admit-individual-64 | 64 | unavailable: refused | not fitted | 0.000 000 351 | refused |
| admit-policy-4 | 4 | unavailable: refused | not fitted | 0.000 000 401 | refused |
| admit-policy-16 | 16 | unavailable: refused | not fitted | 0.000 000 682 | refused |
| admit-policy-64 | 64 | unavailable: refused | not fitted | 0.000 000 411 | refused |
| trials-serial-1 | 1 | 100 853 877.4 | 100 644 312.662 500 01 to 101 066 145.197 5 | 0.000 000 481 | passed |
| trials-serial-2 | 2 | 264 073 547.1 | 223 891 589.785 000 03 to 305 473 344.267 5 | 0.000 000 712 | passed |
| trials-serial-4 | 4 | 399 959 465.9 | 398 641 760.575 to 401 670 644.022 5 | 0.000 000 811 | passed |
| trials-serial-8 | 8 | 846 568 191.6 | 824 969 150.665 000 1 to 872 846 225.875 | 0.000 004 488 | passed |
| scalar-rational-1 | 1 | unavailable: refused | not fitted | unavailable | refused |
| scalar-rational-2 | 2 | unavailable: refused | not fitted | unavailable | refused |
| scalar-rational-4 | 4 | unavailable: refused | not fitted | unavailable | refused |
| scalar-rational-8 | 8 | unavailable: refused | not fitted | unavailable | refused |
| scalar-ridge-1 | 1 | unavailable: refused | not fitted | 0.000 000 11 | refused |
| scalar-ridge-2 | 2 | 180 006 324.1 | 177 464 566.577 5 to 182 486 611.455 | 0.000 000 101 | passed |
| scalar-ridge-4 | 4 | 187 042 161.7 | 183 963 258.527 5 to 189 887 167.345 | 0.000 000 1 | passed |
| scalar-ridge-8 | 8 | 186 906 477.4 | 183 902 431.752 5 to 189 497 701.247 5 | 0.000 000 141 | passed |
