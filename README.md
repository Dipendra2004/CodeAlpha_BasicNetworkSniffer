# CodeAlpha Basic Network Sniffer

Advanced command-line packet sniffer built with Python and Scapy.
The project supports live packet capture, protocol-aware parsing, JSONL/PCAP exports, offline PCAP analysis, interface discovery, and operational troubleshooting for Windows environments.

## Project Highlights

- Live sniffing with interface selection by name or index
- Protocol filters: all, tcp, udp, icmp, arp, dns, http, tls
- Optional BPF filtering for targeted capture expressions
- Real-time console output with transport and app-level hints
- Structured JSONL output for analysis pipelines
- PCAP export for Wireshark and forensic workflows
- Offline PCAP replay and analysis mode
- Capture session summary (throughput, top IPs, top ports)
- Friendly Windows interface listing with default-route marker
- Defensive CLI UX and clear error handling

## Tech Stack

- Python 3.x
- Scapy 2.5+
- Windows PowerShell / Terminal

## Repository Structure

```text
.
|-- network_sniffer.py      # Main CLI application
|-- requirements.txt        # Python dependencies
|-- README.md               # Project documentation
`-- .gitignore              # Git ignore rules
```

## How It Works

1. CLI arguments are parsed (interface, filters, mode, output targets).
2. Packets are captured from live interface or replayed from PCAP file.
3. Each packet is parsed into a normalized event model.
4. Events are filtered, printed, optionally logged to JSONL, and optionally written to PCAP.
5. Session statistics are accumulated and printed at the end.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Command Reference

### 0) Check tool version

```powershell
python network_sniffer.py --version
```

### 1) List interfaces (recommended first step)

```powershell
python network_sniffer.py --list-interfaces
```

### 2) Live capture by interface index

```powershell
python network_sniffer.py --iface-index 5 --count 50 --timeout 20
```

### 3) Live capture by explicit interface name

```powershell
python network_sniffer.py "Wi-Fi" --count 50 --timeout 20
```

### 4) Protocol-focused capture (example: DNS)

```powershell
python network_sniffer.py --iface-index 5 --protocol dns --timeout 60
```

### 5) BPF + JSONL + PCAP export

```powershell
python network_sniffer.py --iface-index 5 --bpf "tcp or udp" --json-log live.jsonl --pcap-output live.pcap --timeout 30
```

### 6) Offline analysis from an existing capture

```powershell
python network_sniffer.py --read-pcap demo_capture.pcap --protocol all --verbose
```

## Sample Output

```text
2026-03-20T22:28:40.828 | UDP   [DNS]  | 10.0.0.5 -> 8.8.8.8 53123->53 | len=71 | DNS query example.com
2026-03-20T22:28:40.830 | TCP   [TLS]  | 10.0.0.5 -> 142.250.183.78 50000->443 | len=54 | flags=S seq=0

Capture Summary
Duration: 0.02s
Packets: 2
Bytes:   125
Rate:    129.95 packets/s | 8122.16 bytes/s
```

## Windows Live Capture Requirements

1. Install Npcap from https://npcap.com/#download
2. Enable WinPcap API-compatible mode in Npcap installer
3. Run terminal as Administrator for live capture
4. Select the active physical adapter (usually Wi-Fi or Ethernet)

## Troubleshooting

- Error: interface not found
Action: run --list-interfaces and use exact index/name.

- Capture summary shows 0 packets
Action: verify adapter index, generate traffic during capture, and avoid inactive virtual adapters.

- Npcap/WinPcap unavailable message
Action: reinstall Npcap with compatibility mode and retry from admin terminal.

## Roadmap

- Connection/flow tracking dashboards
- Detection rules (scan/flood heuristics)
- Export integrations for SIEM-ready workflows

## License

This project is for educational and internship learning purposes.
