# PCAP Analyzer

[![CI](https://github.com/11arkan/pcap-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/11arkan/pcap-parser/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A desktop application for analyzing PCAP and PCAPNG network capture files, built with Electron, React, and TypeScript. Drop a Wireshark capture and instantly get IP enrichment, geolocation, traffic charts, stream inspection, and optional Process Monitor correlation.

---

## Features

- **Packet parsing** — `.pcap`, `.pcapng`, `.cap`, `.dmp` files
- **IP enrichment** — WHOIS/ASN lookups via RIPE, RDAP, and ip-api (with 24 h local cache)
- **Geolocation** — country, city, region, and flag display per IP
- **ISP & organization** identification
- **ASN / CIDR grouping**
- **Interactive charts** — top countries, ASNs, services, and protocol distribution
- **Sortable data tables** — public and local IP views with search/filter
- **Stream reconstruction** — TCP/UDP stream catalog with per-packet hex/ASCII payload viewer
- **Export** — CSV, JSON, and Excel for both connection tables and stream data
- **Process Monitor correlation** — match network sessions to Windows processes using `.pml` logs from Procmon
- **Multi-tab analysis** — open and compare multiple capture files side by side

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) (runtime & package manager)
- [Node.js](https://nodejs.org/) (required by Electron)
- Windows, macOS, or Linux

### Install

```bash
bun install
```

### Run (development)

```bash
bun run dev
```

### Build

```bash
bun run build
```

### Package (Windows installer)

```bash
bun run dist
```

The installer is written to `release/`.
This is the same installer variant intended for GitHub Releases.
End users do not need a system-wide Python installation.
The release pipeline prepares and bundles the correlation runtime in advance: embedded Python, `pip` packages from `sidecar/requirements.txt`, and the bundled Sysinternals Process Monitor binary.
During installation the bootstrap script mainly verifies that runtime and only falls back to downloading missing pieces if the bundled copy is incomplete.

### Internal package (auto dependencies on install)

```bash
bun run dist:internal
```

This build creates a non-public installer in `release/internal/`.
During installation, the installer bootstraps embedded Python and installs sidecar dependencies automatically (no manual `pip install` on end-user machines).

## GitHub Releases

Tagging a version such as `v1.0.3` triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which:

- builds the standard Windows NSIS installer on `windows-latest`
- prepares the bundled Python sidecar runtime before packaging
- uploads the generated installer artifacts to the matching GitHub Release
- keeps the same runtime bootstrap as `dist:internal`, so end users do not need to install Python, Procmon, or sidecar packages by hand

## Testing

```bash
# All tests
bun test

# Capture/table regression tests only
bun run test:captures
```

## Quality Gates

| Check | Command |
|---|---|
| Type-check | `bunx tsc --noEmit` |
| Tests | `bun test` |
| CI | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

## Process Monitor Correlation

The correlation feature matches PCAP network sessions with [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) logs to identify which Windows process originated each connection.

It runs in a Python sidecar and uses:

1. Procmon XML export (`/OpenLog` + `/SaveAs2`) as the canonical source.
2. Optional [`procmon-parser`](https://pypi.org/project/procmon-parser/) enrichment when available.

### Setup

1. Install Python dependencies:

   ```bash
   bun run sidecar:install-deps
   ```

2. Place the Procmon binary at `vendor/procmon/Procmon64.exe` (or set the `PCAP_ANALYZER_PROCMON` env var).

3. Optionally set `PCAP_ANALYZER_PYTHON` to a custom Python path.

### Packaging

`electron-builder` copies the following into the app resources:

| Source | Destination |
|---|---|
| `sidecar/` | `resources/sidecar` |
| `vendor/procmon/` | `resources/procmon` |
| `python/` | `resources/python` |

The NSIS installer then runs `sidecar/install_runtime.ps1`, which verifies or installs:

- embedded Python runtime in `resources/python`
- `pip`
- packages from `sidecar/requirements.txt` including `procmon-parser`
- Process Monitor binaries in `resources/procmon`

For GitHub Releases, the repository prepares that runtime ahead of time with:

```bash
bun run runtime:prepare
```

This makes the packaged installer self-sufficient on machines without Python.

## Technology Stack

- Electron + TypeScript for the desktop shell and IPC bridge
- React for the renderer UI
- Recharts for charts and traffic visualizations
- PapaParse and SheetJS (`xlsx`) for export/import workflows
- Python sidecar for Procmon correlation
- Sysinternals Process Monitor for Windows process/network event correlation
- RIPE / RDAP / ip-api for IP enrichment data

## Project Structure

```text
pcap-analyzer/
├── main.ts                        # Electron main process
├── preload.ts                     # Context bridge (IPC)
├── src/
│   ├── App.tsx                    # Root React component
│   ├── index.tsx                  # Entry point
│   ├── styles.css                 # Global styles
│   ├── types.ts                   # Shared TypeScript types
│   ├── components/
│   │   ├── Charts.tsx             # Recharts visualizations
│   │   ├── CorrelationPanel.tsx   # Process Monitor correlation UI
│   │   ├── DataTable.tsx          # Sortable connection table + export
│   │   ├── DropZone.tsx           # Drag-and-drop file input
│   │   ├── LoadingOverlay.tsx     # Progress overlay
│   │   └── StreamsPanel.tsx       # TCP/UDP stream viewer
│   ├── main/
│   │   └── correlationJobManager.ts  # Sidecar process manager
│   └── utils/
│       ├── correlationSummary.ts  # Correlation report aggregation
│       ├── pcapParser.ts          # Binary PCAP/PCAPNG parser
│       ├── pcapStreams.ts         # Stream reconstruction
│       ├── streamFilter.ts       # Stream search/filter DSL
│       ├── streamsExcelExport.ts  # Streams Excel export
│       └── whoisApi.ts           # Client-side WHOIS cache
├── sidecar/                       # Python correlation scripts
├── tests/                         # Bun test suite
├── captures/                      # Sample PCAP fixtures
└── dist/                          # Build output
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
