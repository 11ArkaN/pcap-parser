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

MIT
