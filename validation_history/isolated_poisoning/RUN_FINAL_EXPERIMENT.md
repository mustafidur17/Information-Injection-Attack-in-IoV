# Run the final matched experiment

Extract the complete ZIP. Open Command Prompt inside the extracted `Content Poisoning` folder, where `one.bat`, `target`, `lib`, and both final configurations are located.

The supplied compiled classes require **Java 17 or newer**. The project was clean-compiled with OpenJDK 17.0.20. If rebuilding on Windows, use an installed JDK and a Java runtime compatible with that compiler. Check `java -version` and `javac -version` if your PC has multiple Java installations.

Optional rebuild:

```bat
compile.bat
```

Final Normal experiment:

```bat
one.bat -b 150 CCN_Normal_configuration.txt
```

Final Attack experiment:

```bat
one.bat -b 150 Malicious_injection.txt
```

Running these commands sequentially is sufficient. Each command executes 150 simulations. Each simulation lasts **86,400 simulated seconds**, not a promised 24 hours of wall-clock execution. Reports are written to `reports/`, with distinct Normal/Attack prefixes and interval, TTL, buffer and seed in each filename.

Both final configurations use:

```text
SinkCCN.interval = [1800;1200;600]
Group.bufferSize = [5k;10k;20k;40k;80k]
Group.msgTtl = [60;120;180;240;300]
MovementModel.rngSeed = [1;2]
Settings.cartesianRunSettings = SinkCCN.interval,Group.bufferSize,Group.msgTtl,MovementModel.rngSeed
```

The actual parser was checked at every run index from 0 to 149. It produces **3 x 5 x 5 x 2 = 150 unique combinations** in the same order for both scenarios. Seed varies fastest, then TTL, buffer, and interval. The complete evaluated matrices are in `validation/logs/audit_normal.log` and `validation/logs/audit_attack.log`.

`validation/` contains short test configurations and diagnostic outputs. Those files are separate from the final experiment. Use the two commands above for your research runs. Do not mix validation reports with final reports in OppNDA.

The empty `Group4.bufferSize =` and `Group5.bufferSize =` assignments are intentional. This project's Settings parser falls back to `Group.bufferSize` when the primary group setting is empty. They cancel the inherited 50M values from `default_settings.txt`; removing these assignments would silently defeat the producer buffer sweep.

To reproduce an individual pilot, for example:

```bat
one.bat -b 1 CCN_Normal_configuration.txt validation/configs/pilot_Normal_5k.txt
one.bat -b 1 Malicious_injection.txt validation/configs/pilot_Attack_80k.txt
```

Each pilot uses 21,600 simulated seconds, interval 600, TTL 180, seed 1. Pilot outputs stay under `validation/reports/`.
