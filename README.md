# PCAP Analyzer

Nowoczesna aplikacja desktopowa do analizy plikow PCAP/PCAPNG z Wiresharka.

## Funkcjonalnosci

- Parsowanie plikow .pcap, .pcapng, .cap
- Ekstrakcja adresow IP (publiczne i lokalne)
- Pobieranie danych WHOIS/ASN z API ipwho.is
- Geolokalizacja IP (kraj, miasto)
- Identyfikacja ISP i organizacji
- Grupowanie po ASN i CIDR
- Wizualizacja danych (wykresy)
- Eksport do CSV, JSON, Excel
- Cache danych WHOIS (24h)

## Wymagania

- [Bun](https://bun.sh/) - srodowisko uruchomieniowe JavaScript
- Windows/macOS/Linux

## Instalacja

```bash
# Zainstaluj zaleznosci
bun install

# Zbuduj aplikacje
bun run build
```

## Uruchomienie

```bash
# Tryb deweloperski
bun run dev

# Lub produkcyjny
bun run start
```

## Uzycie

1. Uruchom aplikacje
2. Przeciagnij plik PCAP na obszar "Drop zone" lub kliknij "browse"
3. Poczekaj na parsowanie i pobranie danych WHOIS
4. Przegladaj dane w zakladkach:
   - **Public IPs** - adresy publiczne z danymi WHOIS
   - **Local Network** - adresy lokalne (192.168.x.x, 10.x.x.x)
5. Eksportuj dane do CSV, JSON lub Excel

## Testowanie

W folderze `captures/` znajduje sie plik testowy `Wifi.pcapng`.

```bash
# Test parsera
bun test-parser.js
```

## Struktura projektu

```
pcap-analyzer/
├── main.js              # Proces glowny Electron
├── preload.js           # Bridge Electron <-> React
├── src/
│   ├── App.jsx          # Glowny komponent
│   ├── index.js         # Entry point React
│   ├── styles.css       # Style CSS
│   ├── components/      # Komponenty React
│   │   ├── DropZone.jsx
│   │   ├── DataTable.jsx
│   │   ├── Charts.jsx
│   │   └── LoadingOverlay.jsx
│   └── utils/           # Narzedzia
│       ├── pcapParser.js
│       └── whoisApi.js
├── captures/            # Pliki testowe
└── dist/                # Zbudowane pliki
```

## Technologie

- Electron - framework desktopowy
- React - biblioteka UI
- Recharts - wykresy
- ipwho.is API - dane WHOIS (darmowe)
- XLSX - eksport Excel
- PapaParse - eksport CSV

## Wdrozenie

### Windows
```bash
bun run build
# Pliki w dist/
```

### Tworzenie instalatora
```bash
# Wymaga electron-builder
bun add -d electron-builder
bun run dist
```

## Licencja

MIT
