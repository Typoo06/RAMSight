# Rules

Configuration for YARA signatures, Sigma reference rules, detection rules, and risk scoring.

Do not place malware samples or memory dumps here.

Active YARA runtime packs are generated under `rules/yara/compiled/` from validated third-party sources in `rules/yara/third_party/`. Archived RAMSight demo YARA rules live under `rules/yara/disabled/archive/` and are not used for detection.

SigmaHQ rules, when imported, live under `rules/sigma/third_party/` as reference/future correlation content only. They are not passed to Volatility YARA scanning.

See `docs/YARA_RULES.md` and `docs/rules/THIRD_PARTY_RULES.md` for import, validation, attribution, and demo guidance.
