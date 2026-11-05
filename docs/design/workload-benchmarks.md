# Structural workload measurements · `rec:design:workload-benchmark-series`

**Convention (Workload inputs)** · `conv:harness:workload-benchmark-inputs` Component curves measure a declared deterministic recipe through public constructors and validators. Correctness is checked before sampling and after the timed series; input construction is excluded, while allocations made by the operation and destruction of its returned owned output remain timed. Consuming marker operations receive a fresh input clone outside each timed iteration. Fixture proof equality measures structural evidence handling, not cryptographic verification or chain finality. A refused, unsupported or incomplete point remains an explicitly typed result and cannot be fitted as successful throughput. Source, configuration, dimensions, limits, setup, raw samples and resource scope accompany every measurement. Resource samples describe the build container's cgroup, not other logins or the node as a whole; waited process accounting gives the campaign's own CPU. Load averages are recorded as context, without attributing their activity to other logins. These curves declare no host workload, production API limit or capacity.

**Record (Sampling contract)** · `rec:workload:sampling` Full campaigns use 10 samples, 100 ms warm-up, 1 000 ms measurement targets and 1 000 statistical resamples, with flat iteration scheduling. The profile is gate and the deterministic seed is 0. These are bounded sampling settings, not elapsed deadlines: a slow operation completes and retains its measured cost. A serialized pilot precedes a full series. The existing foundation smoke retains its settings; the extra smoke points are declared in the grid carrier. Full campaigns run serially at idle priority on a recorded allowed CPU with a separate build target. Timing is nonverdict under (`rule:devperf:nonverdict`). The dataset names each package-owned construction control. Result association is checked by (`claim:harness:workload-result-binding`).

## Declared grids · `sec:workload:grids`

| Grid | Package and target | Sizes | Variants | Timed | Excluded |
| --- | --- | --- | --- | --- | --- |
| B1 | pn-records / workload-records | 16, 64, 256, 1 024 complete acts | parallel, mixed | validate_history, including returned owned output destruction | raw construction and correctness checks |
| B13 | pn-records / workload-records | 1, 4, 16, 64 markers including initial marker | list, commitment | validate_marker_history followed by recognize_markers, including returned owned output destruction | raw construction, burn and policy binding, correctness, per-iteration input clone |
| B14 | pn-interchange / workload-transport | 256, 1 024, 4 096, 16 384 payload bytes | strict, chunked | strict or transport decoding and owned output destruction; transport counters include the decoder's allocations | payload and canonical/chunked encoding construction, correctness |

**Record (Act history curve)** · `rec:workload:act-history` The act grid measures complete-history structural validation with distinct act identities and fixed Actor names over a shared endpoint. Its mixed variant alternates complete binary and paired fixture families. It does not execute the epoch compiler's family formation or establish authentication validity. The recipe and sizes live in the workload dataset; no paper wall bound is inferred for the complete validator.

**Record (Marker history curve)** · `rec:workload:marker-history` The marker grid measures validation and recognition together, with policy and burn binding prepared before timing. The initial marker has an empty accepted set; successors repeat a complete accepted singleton with valid lineage and predecessor links. List and commitment representations are separate curves. The commitment fixture checks the complete opening bytes; no real settlement latency is represented by its synthetic positions.

**Record (Transport byte curve)** · `rec:workload:codec-bytes` The byte grid compares strict canonical byte strings with allowed indefinite transport strings over equal payloads. Empty chunks remain legal and are included. Each transport operation receives explicit input, allocation, item, depth, nesting and work limits from the experiment recipe. The decoder's reservation counter explains requested allocation work; it is not a general allocator or peak-memory measurement.

## Campaign evidence · `sec:workload:campaigns`

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
| Measured source | Public base | Exercised tree | Scheduling and machine |
| --- | --- | --- | --- |
| kranich-structural-pilot | `ad94eb24887ecbda0f34a95884ca99b7f6f504e9` | `4879e68b530c75f771813625a033c86be8c4d1eb` | kranich; AMD Ryzen 9 5950X 16-Core Processor; SCHED_IDLE. Measured tree before signing/import; public commit locator pending import under campaign-tree admission. |
| kranich-structural-full | `ad94eb24887ecbda0f34a95884ca99b7f6f504e9` | `4879e68b530c75f771813625a033c86be8c4d1eb` | kranich; AMD Ryzen 9 5950X 16-Core Processor; SCHED_IDLE. Measured tree before signing/import; public commit locator pending import under campaign-tree admission. |

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
