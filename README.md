# Proof of Mood — ARP Scanner

Lightweight Python ARP scanner with optional MAC vendor lookup and simple OS guess based on ICMP TTL.

---

## Features

* ARP discovery for a target subnet (e.g. `192.168.1.0/24`).
* Basic OS guess using ICMP reply TTL ("Linux/Unix" vs "Windows").
* Optional MAC vendor lookup (uses `api.macvendors.com`) with a small local cache (`~/.cache/arp_scanner_vendors.json`).
* Clean, terminal-friendly output and a small loading animation while scanning.

---

## Requirements

* Python 3.8+ (tested with Python 3.9+)
* `scapy` (required)
* `requests` (optional — required only when using `--vendor`)

Install dependencies with pip:

```bash
pip install scapy requests
```

> If you don't install `requests`, the script will still run but vendor lookup will be disabled.

---

## Usage

Make the script executable or run with Python:

```bash
# run directly
python arp_scanner.py -t 192.168.1.0/24

# specify interface and enable vendor lookup
python arp_scanner.py -t 192.168.1.0/24 -i wlan0 --vendor
```

### Important

* The script uses raw sockets via `scapy` and typically **requires root/administrator privileges**. Run with `sudo` on Linux/macOS:

```bash
sudo python arp_scanner.py -t 192.168.1.0/24 --vendor
```

* The `--vendor` flag will query `https://api.macvendors.com/` to resolve MAC OUIs to vendor names. Results are cached in `~/.cache/arp_scanner_vendors.json` to reduce network calls.

---

## Output

When run, the script prints an ASCII banner and a single-line scanning status that animates while the scan runs. After the scan completes, it overwrites the scanning line and prints `[*] Scanning completed.` followed by a table of discovered devices.

Columns (when `--vendor` not used):

* `IP` — IPv4 address of discovered host
* `MAC` — normalized MAC address (AA:BB:CC:...)
* `OS` — best-effort OS guess based on ICMP TTL

Columns (when `--vendor` used) add a `Vendor` column containing the MAC vendor (or `Unknown Vendor` / `N/A`).

---

## Cache details

* Cache file: `~/.cache/arp_scanner_vendors.json`
* The script currently caches vendor lookups keyed by the MAC OUI (first 3 bytes). There is no TTL implemented by default — if you want cache expiration or `--no-cache`, you can add it manually.

---

## Troubleshooting

* **No results / empty output**: Ensure you specified the correct target subnet and interface. Try a smaller range (single IP) or run without `--vendor` to check basic discovery.
* **PermissionError**: Run with elevated privileges (e.g. `sudo`).
* **Missing scapy**: Install with `pip install scapy`.
* **Vendor lookup disabled**: If `requests` is not installed, the script will inform you and continue without vendor lookups.

---

## Security & Ethics

This tool performs network discovery on a local network. Use it only on networks you own or are authorized to test. Unauthorized scanning of networks may be illegal or violate acceptable-use policies.

---

## License

MIT License — copy, modify and use at your own risk.

---

## Contact / Improvements

If you want extra features (CSV/JSON export, cache TTL, offline OUI file, parallelized ICMP checks, colored output, or a quieter/verbose mode), tell me which one and I can help add it.
