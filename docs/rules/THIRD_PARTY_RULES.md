# Third-Party Rule Packs

RAMSight integrates third-party detection content as pinned local rule packs. Normal app runtime must not fetch rules from GitHub.

## Sources

| Pack | Source | Runtime use |
| --- | --- | --- |
| `elastic_yara` | `https://github.com/elastic/protections-artifacts` | Volatility `windows.vadyarascan` YARA scanning |
| `neo23x0_yara` | `https://github.com/Neo23x0/signature-base` | Volatility `windows.vadyarascan` YARA scanning |
| `third_party_yara_all` | Elastic + Neo23x0 compiled together | Optional heavy profile only |
| SigmaHQ reference | `https://github.com/SigmaHQ/sigma` | Reference/future correlation metadata only |

## Attribution And Licenses

Import scripts preserve upstream rule files and copy license or notice files when present. Manifest files record the source URL, ref, commit hash, license label, imported paths, compile status, disabled files, and import timestamp.

Do not rewrite third-party rules silently. If compatibility changes are ever required, keep the original upstream copy unchanged and place modified copies in a separate overlay directory with notes.

## Operational Notes

- Validate every `.yar` and `.yara` file independently before building runtime packs.
- Quarantine compile failures under `rules/yara/disabled/<source>/` and record the compile error in the manifest.
- Do not concatenate every rule blindly at runtime. Build explicit active packs with `scripts/rules/build_yara_pack.py`.
- Use `windows_memory_yara_elastic` for the standard thesis demo path.
- Use `windows_memory_yara_third_party_all` only when scan time and worker resources are acceptable.

## Demo Checklist

1. Start Docker stack.
2. Import or verify third-party rule packs are present.
3. Run `python scripts/rules/validate_yara_rules.py`.
4. Build `elastic_yara` with `python scripts/rules/build_yara_pack.py --pack elastic_yara`.
5. Upload/register a Windows memory dump from the lab.
6. Select `windows_memory_yara_elastic`.
7. Start analysis.
8. Review plugin results, suspicious findings, IOC records, and the HTML report.

PDF export is not implemented in the current demo build.
