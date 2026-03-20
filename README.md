# Advanced Packet Sniffer (Scapy)

An upgraded network sniffer with protocol-aware analysis, filtering, structured logging, and PCAP export.

## Features

- Real-time packet capture on a selected interface
- BPF filtering (tcp/udp/port/host expressions)
- Interface discovery mode (`--list-interfaces`)
- Protocol filters: `all`, `tcp`, `udp`, `icmp`, `arp`, `dns`, `http`, `tls`
- Application hints for DNS/HTTP/TLS traffic
- Optional payload preview mode
- JSONL event logging for SIEM/data processing
- PCAP output compatible with Wireshark
- Offline packet analysis from PCAP files
- Capture statistics summary (rates, top IPs, top ports)

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

### Basic capture

```powershell
python network_sniffer.py "Wi-Fi"
```

### List interfaces

```powershell
python network_sniffer.py --list-interfaces
```

### Capture only DNS traffic for 60 seconds

```powershell
python network_sniffer.py "Wi-Fi" --protocol dns --timeout 60
```

### Use BPF + save JSON logs + save PCAP

```powershell
python network_sniffer.py "Wi-Fi" --bpf "tcp or udp" --json-log capture.jsonl --pcap-output capture.pcap
```

### Verbose payload preview (first 120 bytes)

```powershell
python network_sniffer.py "Wi-Fi" -v --payload-bytes 120
```

### Analyze an existing PCAP file (no live capture needed)

```powershell
python network_sniffer.py --read-pcap capture.pcap --protocol dns --count 200
```

## Notes

- Run terminal as Administrator on Windows if packet capture fails.
- If Npcap/WinPcap is not available, the tool attempts a layer-3 fallback automatically.
- Install Npcap with WinPcap compatibility mode for full layer-2 capture support.
- Interface names can be listed with Scapy if needed:

```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

- Use `network_sniffer.py` as the main and only sniffer entrypoint.
