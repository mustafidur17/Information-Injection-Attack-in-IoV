# Validation report

## Scope and build

The newest uploaded ZIP was inspected and corrected. The actual `compile.sh` build completed from a clean target after removing stale source-tree class files. Compiler: OpenJDK 17.0.20; class format: Java 17 (major 61). Compilation produced 220 classes, no errors and 17 existing deprecation/removal warnings, plus existing deprecated-API/unchecked-operation notes. Both compile scripts now propagate compiler failure.

Four final clean-build map-based pilots completed, using the final 100-node layout and matched parameters. Each pilot used interval 600 seconds, TTL 180 minutes, mobility seed 1 and either 5k or 80k buffers. End time was temporarily 21,600 seconds in separate overlays. The native simulator reported 21,600.1 seconds because of its floating-point update loop and 0.1-second tick. The main files remain at 86,400 seconds.

The clean-build pilots took about 10-15 seconds each in this environment. This is a record of those tests, not a wall-time promise for your full experiment. No 150-run Normal or 150-run Attack simulation batch was launched. The 150-index audit evaluated settings without running those simulations.

## CCN results

| Metric | Normal 5k | Normal 80k | Attack 5k | Attack 80k |
| --- | ---: | ---: | ---: | ---: |
| query_count | 183 | 182 | 183 | 182 |
| response_count | 166 | 167 | 166 | 167 |
| false_content_generated | 0 | 0 | 122 | 129 |
| false_content_cached | 0 | 0 | 2417 | 2474 |
| false_content_received | 0 | 0 | 141 | 142 |
| legitimate_content_received | 166 | 167 | 25 | 25 |
| false_content_reception_ratio | 0 | 0 | 0.84939759 | 0.850299401 |
| legitimate_content_satisfaction_ratio | 0.907103825 | 0.917582418 | 0.136612022 | 0.137362637 |
| total_cache_evictions | 2400 | 2532 | 2400 | 2532 |
| legitimate_content_evicted_by_false | 0 | 0 | 280 | 325 |
| max_cache_occupancy | 10 | 10 | 10 | 10 |
| max_false_content_in_cache | 0 | 0 | 10 | 10 |
| max_false_cache_ratio | 0 | 0 | 1 | 1 |
| oppo_cache_hit | 16 | 13 | 16 | 13 |
| oppo_cache_miss | 494 | 537 | 494 | 537 |
| average_interval | 1730.124096385 | 1716.989221557 | 1730.124096385 | 1716.989221557 |

All requested false-content fields in Normal are zero. All desired indicators of an active attack are nonzero in the Attack endpoint pilots. Each response_count equals false_content_received plus legitimate_content_received. All requested ratios remain in [0,1].

## DTN results and buffer decision

| Metric | Normal 5k | Normal 80k | Attack 5k | Attack 80k |
| --- | ---: | ---: | ---: | ---: |
| created | 344 | 352 | 344 | 352 |
| started | 170126 | 136073 | 170126 | 136073 |
| relayed | 170125 | 136072 | 170125 | 136072 |
| dropped | 14067 | 5976 | 14067 | 5976 |
| removed | 152211 | 122764 | 152211 | 122764 |
| delivered | 179 | 179 | 179 | 179 |
| delivery_prob | 0.5203 | 0.5085 | 0.5203 | 0.5085 |
| overhead_ratio | 949.419 | 759.1788 | 949.419 | 759.1788 |
| latency_avg | 848.7994 | 881.3385 | 848.7994 | 881.3385 |
| latency_med | 742.8 | 670.5 | 742.8 | 670.5 |
| hopcount_avg | 8.5475 | 9.0838 | 8.5475 | 9.0838 |
| buffertime_avg | 159.4364 | 491.7664 | 159.4364 | 491.7664 |

Decision: retain `[5k;10k;20k;40k;80k]`. Eleven of the twelve compared DTN fields changed between 5k and 80k; delivered stayed at 179. The 1k diagnostic was unnecessary. The range was validated by its endpoints at one representative condition, not by testing every interior level or every final combination. Some final combinations may remain insensitive to buffer size.

Matched Normal and Attack transport fields are identical at each buffer endpoint. This is consistent with changing content legitimacy while preserving message sizes, routing and dissemination resources. The CCN integrity metrics reveal the attack: legitimate satisfaction falls from roughly 0.91 to 0.14 in these pilots. No routing, size or attack-resource change was introduced to separate transport graphs.

## Controlled source-path verification

`tools/ContentPathValidation.java` uses instantiated project hosts, actual application handlers, MessageRouter receive/transfer processing and the actual LRU implementation. Transfers are deliberately controlled for the regression test and do not replace the map-based pilot data. It verifies:

- Generated 73-byte Interests and independently configured 211-byte Content Objects, without changing final 50/150 settings.
- Two responses created at the same simulated time retain different IDs.
- Both direct and overheard-Interest malicious producer responses increment false generation.
- A pure DTN node carries CCN properties between router types.
- A false producer response enters a Group 3 intermediate cache; a different consumer later receives a new response from that cache, without contacting the malicious producer.
- Stored content, message replication and the subsequent cache response preserve the false marker.
- Normal consumers count legitimate content; Attack consumers count the corresponding false content.
- A multicast response is forwarded when exactly one recipient remains.
- The 10-entry LRU stays bounded, exposes the evicted value and does not report an in-place key update as a capacity eviction.
- Both reporters retain a 0.375-second average interval, produce correct satisfaction arithmetic and return zeros when no queries or responses exist.

See `validation/logs/functional_normal.log`, `functional_attack.log`, `verification.log`, and the separate functional/zero report directories. Those controlled reports are regression fixtures, not research observations.

## Exact metric semantics and remaining limits

- `query_count` counts emitted Interests. The existing application skips generation when the name is cached or already outstanding, reporting these skips as duplicated_query. Thus the configured interval is an attempt interval, and satisfaction is measured over emitted Interests, not every attempted demand.
- `response_count` and the false/legitimate reception counters count the first accepted content for an outstanding consumer/name entry. A matching passing Content Object can satisfy an outstanding query even if its DTN destination is another consumer. Duplicate Content transfers are not automatically additional satisfied queries.
- `legitimate_content_satisfaction_ratio = legitimate_content_received / query_count`, or 0.0 with no queries.
- `false_content_reception_ratio = false_content_received / (false_content_received + legitimate_content_received)`, or 0.0 with no accepted content.
- `false_content_cached` counts false cache-write events, including repeated writes of the same name; it is not the number of distinct poisoned names or nodes.
- `total_cache_evictions` counts capacity evictions from opportunity caches. `legitimate_content_evicted_by_false` counts an incoming false item causing an LRU capacity eviction of legitimate content. In-place replacement of an existing key is not a capacity eviction under the retained metric definition.
- `max_cache_occupancy` and `max_false_content_in_cache` are maxima at one opportunity cache over observed updates. `max_false_cache_ratio` is false entries divided by that cache's capacity, then maximized over hosts/time. It is not a network-wide average or the fraction of occupied entries that are false.
- Cache events aggregate CCN applications, including producer opportunity caches, in both scenarios. Producer static preloads are not counted as opportunity-cache insertions. DTN router buffer bytes are separate from the 10-entry opportunity caches.
- `false_content_generated` counts new false responses from malicious static content, including the overheard-Interest path. A normal node re-serving a cached poisoned value contributes to subsequent caching/reception, not fresh malicious-static generation.
- `average_interval` is the mean elapsed simulated time for satisfied emitted queries, matched by consumer and content name; it includes false and legitimate satisfied queries. Unsatisfied queries are excluded.
- The existing PIT and outstanding-query structures do not implement Interest-expiry cleanup. An unanswered name can suppress later requests for that name. The swept Group.msgTtl controls DTN bundle lifetime, not a newly implemented CCNx InterestLifetime. This retained model limitation matters when explaining the TTL results in the paper.
- THE ONE's built-in `response_prob`/`rtt_avg`/`rtt_med` track its separate automatic request-response mechanism. These CCN packets do not use that mechanism, so response_prob is 0 and RTT values are NaN (undefined), even when CCN responses succeed. Use CCN response_count and average_interval for CCN outcomes. Required primary metrics and requested secondary comparison fields are finite in the pilots. Undefined RTT entries are represented as null in the JSON companion.
- Two mobility seeds were retained exactly as requested. They provide limited independent replication; the pilots do not establish confidence intervals, significance or all-condition robustness.
- No OppNDA parser was supplied. Internal searches found no parser dependency on oppo_cahce_hit. Metric keys were normalized, but importing into the separate OppNDA installation was not tested. If that external parser hardcodes the old typo, update it to oppo_cache_hit.

One initial concurrent JVM launch failed in native PerfMemory::alloc before simulation startup. The same pilot passed on retry, and all four final clean-build pilots passed sequentially. The JVM startup log is retained under `validation/logs/jvm_startup/`; its native root cause was not determined. No simulator change was made for it.

## Final checklist

| Check | Result |
| --- | --- |
| 100 nodes in each scenario; 80 pure DTN nodes | PASS: actual instantiated hosts and parser |
| Nodes 0-79 have no CCN application | PASS: runtime application collections empty |
| 6 consumers at 80-85, mode 1 | PASS |
| 4 intermediate/cache nodes at 86-89, mode 3 | PASS |
| 6 legitimate producers at 90-95, mode 2 | PASS |
| 4 control/malicious producers at 96-99, mode 2 | PASS |
| Groups 1-4 FirstContactRouter; Group 5 EpidemicRouter in both | PASS: runtime router classes |
| Normal ControlSourceCCN; Attack MaliciousCCN | PASS |
| Matched resources, mobility, interfaces, static caches and application parameters | PASS: normalized final settings compared |
| Sink destinationRange 90,100 reaches exactly 90-99 | PASS: source expression and 1,000 draws covering all ten addresses |
| contentSize controls every active response constructor | PASS: four sites and runtime size 211 in controlled test |
| interestSize independently configurable; final sizes 50/150 | PASS: controlled Interest size 73; final files retain 50/150 |
| Normal and Attack select their respective requested reporter | PASS |
| Common schema and oppo_cache_hit spelling | PASS: equal ordered metric keys; no internal parser dependency |
| Double precision average_interval | PASS: exact 0.375 seconds in both controlled tests |
| legitimate_content_satisfaction_ratio with zero guard | PASS: 2/3 in Normal functional test and 0.0 in both empty reporters |
| false_content_reception_ratio formula and zero guard | PASS |
| Normal false-content counters zero with meaningful CCN traffic | PASS: all requested zero fields, positive queries/responses/legitimate reception |
| Attack generation, caching and reception nonzero | PASS: both endpoint pilots |
| False + legitimate reception equals response_count | PASS: all pilots and controlled path tests |
| All three requested ratios in [0,1] | PASS |
| False marker survives a real producer response, replication, intermediate LRU store and later cache response | PASS: controlled router/application transfer test |
| Cache pollution, eviction metadata and bounded occupancy | PASS: pilots plus LRU test |
| Final duration 86400; names say 24h | PASS: all 150 parser selections |
| Only seeds 1,2; intervals 1800,1200,600; TTLs 60,120,180,240,300 | PASS |
| Five-buffer range 5k,10k,20k,40k,80k | PASS: 5k/80k endpoint sensitivity; interior levels not individually piloted |
| All groups actually use swept router buffer, including producer groups | PASS: evaluated settings at all 150 indices; runtime 5k audit |
| Exactly 150 unique Cartesian settings and report names per configuration | PASS |
| Normal/Attack combinations and order identical | PASS |
| Clean project compilation | PASS: 220 classes; no errors; 17 deprecation/removal warnings |
| Four final clean-build pilots | PASS: 21,600 seconds each, interval 600, TTL 180, seed 1 |
| Full 150 + 150 experiment not launched | CONFIRMED |

## Reproducibility files

- `validation/reports/`: four final pilot report pairs.
- `validation/pilot_results.json`: machine-readable final pilot metrics; undefined legacy RTT values are null.
- `validation/logs/compile_clean.log`: clean build output.
- `validation/logs/audit_normal.log` and `audit_attack.log`: all actual parser combinations and runtime allocation checks.
- `validation/logs/verification.log`: automatic consistency assertions.
- `validation/initial_build_reports/`: earlier pilot outputs retained separately.
- `PROJECT_FILE_CHANGES.txt`: file-level changes compared with the original uploaded archive.

The exact final Windows commands are in `RUN_FINAL_EXPERIMENT.md`.
