# RAMSight YARA Rules

RAMSight uses YARA as a defensive memory-triage aid. Active runtime YARA profiles use validated third-party rule packs only; the old RAMSight demo rules are archived under `rules/yara/disabled/archive/` and are not used for detection.

## Runtime Profiles

- `windows_default`: standard Windows Volatility triage, no YARA.
- `windows_memory_yara`: backward-compatible alias for the Elastic third-party YARA pack.
- `windows_memory_yara_elastic`: recommended demo profile using the compiled Elastic YARA pack.
- `windows_memory_yara_neo23x0`: optional profile using the compiled Neo23x0 Signature Base YARA pack.
- `windows_memory_yara_third_party_all`: baseline Windows triage plus Elastic and Neo23x0 together. Expect slower scans and higher memory use on large dumps.
- `windows_memory_deep_yara_elastic`: deep VAD/injection/thread/module Volatility coverage plus Elastic YARA.
- `windows_memory_deep_yara_neo23x0`: deep VAD/injection/thread/module Volatility coverage plus Neo23x0 YARA.
- `windows_memory_deep_yara_third_party_all`: deep Volatility coverage plus Elastic and Neo23x0 together. This is very slow and intended for advanced investigation only.

The active pack files are generated into:

```text
rules/yara/compiled/elastic_yara.yar
rules/yara/compiled/neo23x0_yara.yar
rules/yara/compiled/third_party_yara_all.yar
```

In Docker development, the compatibility fallback points at the Elastic compiled pack:

```text
VOLATILITY_YARA_RULES_PATH=/rules/yara/compiled/elastic_yara.yar
```

Profile-based worker execution resolves the pack from the selected profile, so `windows_memory_yara` does not use the archived RAMSight demo rules.

## Third-Party Sources

- Elastic protections-artifacts: YARA rules under Elastic License 2.0.
- Neo23x0/signature-base: YARA signatures and IOC data under Detection Rule License 1.1.
- SigmaHQ/sigma: Sigma YAML rules under Detection Rule License 1.1. These are imported as reference/future correlation rules only and are not passed to Volatility YARA scanning.

Preserve upstream rule files, comments, author metadata, README files, license files, and notices. Do not silently edit third-party rules. If a rule fails compilation, quarantine it through the validation manifest and exclude it from active packs.

## Import And Build

Dry-run the import plan:

```bash
python scripts/rules/import_third_party_rules.py --dry-run
```

Import sources when network access is available:

```bash
python scripts/rules/import_third_party_rules.py --source elastic
python scripts/rules/import_third_party_rules.py --source neo23x0_signature_base
python scripts/rules/import_third_party_rules.py --source sigmahq
```

Validate each YARA file independently and quarantine compile failures:

```bash
python scripts/rules/validate_yara_rules.py
```

Build active runtime packs from validated files:

```bash
python scripts/rules/build_yara_pack.py --pack elastic_yara
python scripts/rules/build_yara_pack.py --pack neo23x0_yara
python scripts/rules/build_yara_pack.py --pack third_party_yara_all
```

## Reading Results

YARA matches are stored as `yara_matches`, enriched with source-pack metadata when manifest data is available, converted into cautious risk findings, and shown in the technical HTML report. A YARA hit is not a final malware verdict. Correlate it with `malfind`, process ancestry, command line, network activity, loaded modules, and analyst notes.

Raw YARA match count does not linearly inflate process risk. RAMSight groups one process plus one rule as one scoring signal; broad or generic rules should remain low/medium unless correlated with stronger evidence.

## Limitations

- Third-party YARA packs can be noisy and expensive on large memory dumps.
- `windows_memory_yara_third_party_all` is optional and should be selected deliberately.
- Sigma rules are reference material only in this task; RAMSight does not run a Sigma engine yet.
- PDF export is not implemented in the current demo build; use the HTML report and IOC JSON/CSV exports.
