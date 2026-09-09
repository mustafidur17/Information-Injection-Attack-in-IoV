# Implementation changes

The uploaded `Content Poisoning(1).zip` was the sole project baseline. No older project archive was substituted. The original source, map data, libraries and example material are retained, with current compiled classes under `target/`.

## Final configurations changed

- `CCN_Normal_configuration.txt`
- `Malicious_injection.txt`

Both now contain exactly 100 hosts: 80 pure DTN nodes at 0-79, 6 consumers at 80-85, 4 CCN relays at 86-89, 6 ordinary producers at 90-95 and 4 special producers at 96-99. Groups 1-4 use FirstContactRouter; Group 5 uses EpidemicRouter in both scenarios. Group 1 explicitly has no application. Group 5 has the same host-name prefix in both scenarios to preserve matched host identities.

Normal Group 5 uses ControlSourceCCN with CCN_application; Attack uses MaliciousCCN with MaliciousCCN_application. Group 5 resources match exactly, including a 100-entry static store over 1,101 with seedStaticCache 36, a 10-entry opportunity cache, PIT enabled and the same packet sizes, mobility and interface. Ordinary producers retain their 20-entry static stores. Neither producer group was merged or enlarged.

The settings include the requested three intervals, five TTLs, two seeds, validated five buffers and 86,400-second duration. Scenario/report names consistently use 24h. The normal reporter selection and the broken Attack map path are corrected. Comments now show the actual addresses, dimensions and TTL hours.

The actual default-settings loader always reads `default_settings.txt`. Its Group 4/5 overrides previously supplied 50M buffers and tram mobility, including a second interface on Group 4. The final configurations explicitly override mobility, speed, wait times and interface count, and clear the two producer-specific buffer values so they inherit the Cartesian Group.bufferSize. All 100 instantiated routers now use the selected buffer value. `default_settings.txt` itself is unchanged.

The consumer destination range is 90,100. The same valid producer range is supplied to CCN relays and producers for their cache-miss retargeting path; this prevents ordinary producers from forwarding misses to the default address 0. Normal and malicious random-host selection now share the same inclusive-lower/exclusive-upper implementation.

## Active Java files changed

| File | Change and purpose |
| --- | --- |
| `src/applications/CCN_application.java` | Both inspected response constructors use getContentSize(), while Interest creation still uses getInterestSize(). Response IDs include the originating Interest ID and responder address, preventing same-second response collisions. Retargeted incoming messages return through MessageRouter instead of being counted again as new messages and having their TTL reset. A response with exactly one remaining recipient is now forwarded to that recipient. |
| `src/applications/MaliciousCCN_application.java` | The same size, ID and forwarding corrections. Cache-write, eviction, cache-state and reception instrumentation now matches the normal application. Cached false content restores its Boolean flag on outgoing responses. FalseContentGenerated is counted in both direct and overheard-Interest producer response branches. Destination selection follows the same configured range as the normal application. The false static-content preload and poisoning behavior remain active. |
| `src/report/CCN_application_reporter.java` | Corrected oppo_cache_hit spelling and added guarded floating-point legitimate_content_satisfaction_ratio. Retained every requested common metric. total_interval was already double in this newest upload; it stays double, and total accumulation now resets before calculation so repeated calculation cannot double-count it. |
| `src/report/MaliciousCCN_application_reporter.java` | Identical output-schema, satisfaction-ratio, spelling and interval-accumulation corrections. |

The duplicate source templates `src/New applications/MaliciousCCN_application.java` and `src/New applications/MaliciousCCN_application_reporter.java` were synchronized with their active counterparts. They are not separate compilation inputs. Older editor backups are retained as archival files, not build inputs.

`src/applications/LRUCache.java`, `src/core/Message.java`, `src/core/Settings.java`, FirstContactRouter, EpidemicRouter and the core router implementations were inspected and tested without modification. The existing content string preserves the false-content prefix in the LRU store; Message.copyFrom() copies the message properties. A later cache response reconstructs the false-content flag from that stored string. Both routing protocols use ActiveRouter/MessageRouter and the same application ID; neither requires a same-router peer.

## Build and validation additions

- `compile.sh`: stops on compilation failure.
- `compile.bat`: returns failure if javac fails.
- `tools/ValidateExperiment.java`: audits the real Cartesian parser and instantiated host/router/application settings.
- `tools/ContentPathValidation.java`: exercises the real application/router/cache path under controlled transfers, separately from research data.
- `tools/verify_reports.py`: checks report schemas, arithmetic, counters, matched settings, buffer differences and zero-denominator behavior.
- `validation/configs/`: four six-hour pilot overlays, two controlled functional-test overlays and one empty-reporter overlay. None changes the two final configuration files.

Thirteen stale .class files under src were removed before a clean build. Current target classes were regenerated from the supplied Java source using the actual compile.sh process. The build produced 220 class files. See validation/removed_stale_classes.txt and validation/logs/compile_clean.log.

No internal OppNDA parser dependency on the old misspelling was found. The external OppNDA installation was not supplied and could not be import-tested.
