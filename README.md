# PCAP Analyzer

Desktop app for analyzing PCAP/PCAPNG files from Wireshark.

## Features

- Parsing `.pcap`, `.pcapng`, `.cap`
- Extracting public and local IP addresses
- WHOIS/ASN enrichment via Electron IPC (RIPE + RDAP + ip-api fallback)
- Geolocation (country/city)
- ISP/organization identification
- Grouping by ASN and CIDR
- Charts and tabular analytics
- Export to CSV, JSON, Excel
- Local cache for WHOIS lookups (24h)
- Correlation of PCAP network sessions with Process Monitor `.pml` logs (PID/process mapping)

## Requirements

- [Bun](https://bun.sh/)
- Windows/macOS/Linux

## Install

```bash
bun install
```

## Build

```bash
bun run build
```

## Run

```bash
# Development
bun run dev

# Production
bun run start
```

## Tests

Regression tests are based on files in `captures/` and validate table data outputs.

```bash
# All tests
bun test

# Capture/table regression tests only
bun run test:captures
```

## Quality Gates

- Type-check: `bunx tsc --noEmit`
- Tests: `bun test`
- CI workflow: `.github/workflows/ci.yml`

## Contributing & Security

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`

## Process Monitor Correlation

Correlation runs in a Python sidecar process and uses:

1. Procmon XML export (`/OpenLog` + `/SaveAs2`) as canonical source.
2. Optional `procmon-parser` enrichment when available.

### Dev prerequisites

1. Install Python dependencies:

```bash
bun run sidecar:install-deps
```

2. Put Procmon binary in `vendor/procmon/Procmon64.exe` (or set `PCAP_ANALYZER_PROCMON` env var).
3. Optionally set `PCAP_ANALYZER_PYTHON` to custom Python path.

### Packaging notes

`electron-builder` copies:

- `sidecar/` -> `resources/sidecar`
- `vendor/procmon/` -> `resources/procmon`
- `python/` -> `resources/python`

## Project Structure

```text
pcap-analyzer/
|- main.ts
|- preload.ts
|- src/
|  |- App.tsx
|  |- index.tsx
|  |- styles.css
|  |- types.ts
|  |- components/
|  |  |- DropZone.tsx
|  |  |- DataTable.tsx
|  |  |- Charts.tsx
|  |  |- LoadingOverlay.tsx
|  |- utils/
|     |- pcapParser.ts
|     |- whoisApi.ts
|- tests/
|  |- captures-table-data.test.ts
|- captures/
|- dist/
```

## License

MIT (see `LICENSE`)
