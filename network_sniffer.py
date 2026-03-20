import argparse
import difflib
import json
import logging
import re
import signal
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

APP_VERSION = "1.1.0"

from scapy.all import ARP, DNS, ICMP, IP, IPv6, Raw, TCP, UDP, PcapReader, PcapWriter, conf, get_if_list, resolve_iface, sniff


class PacketStats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self.src_counter: Counter[str] = Counter()
        self.dst_counter: Counter[str] = Counter()
        self.port_counter: Counter[int] = Counter()
        self.start_time = datetime.now()

    def update(self, event: Dict[str, Any], packet_len: int) -> None:
        self.total_packets += 1
        self.total_bytes += packet_len
        self.protocol_counts[event.get("protocol", "UNKNOWN")] += 1

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if src_ip:
            self.src_counter[src_ip] += 1
        if dst_ip:
            self.dst_counter[dst_ip] += 1

        src_port = event.get("src_port")
        dst_port = event.get("dst_port")
        if isinstance(src_port, int):
            self.port_counter[src_port] += 1
        if isinstance(dst_port, int):
            self.port_counter[dst_port] += 1

    def print_summary(self) -> None:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        pps = self.total_packets / elapsed if elapsed > 0 else 0.0
        bps = self.total_bytes / elapsed if elapsed > 0 else 0.0

        print("\n" + "=" * 90)
        print("Capture Summary")
        print("=" * 90)
        print(f"Duration: {elapsed:.2f}s")
        print(f"Packets: {self.total_packets}")
        print(f"Bytes:   {self.total_bytes}")
        print(f"Rate:    {pps:.2f} packets/s | {bps:.2f} bytes/s")

        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_counts.most_common():
            print(f"  - {protocol:<8} {count}")

        print("\nTop Source IPs:")
        for ip, count in self.src_counter.most_common(5):
            print(f"  - {ip:<40} {count}")

        print("\nTop Destination IPs:")
        for ip, count in self.dst_counter.most_common(5):
            print(f"  - {ip:<40} {count}")

        print("\nTop Ports:")
        for port, count in self.port_counter.most_common(10):
            print(f"  - {port:<5} {count}")


class AdvancedSniffer:
    def __init__(
        self,
        interface: str,
        bpf_filter: Optional[str],
        protocol_filter: str,
        verbose: bool,
        payload_preview: int,
        json_log: Optional[str],
        pcap_output: Optional[str],
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.protocol_filter = protocol_filter
        self.verbose = verbose
        self.payload_preview = payload_preview
        self.stats = PacketStats()
        self.stopping = False
        self.log_handle = open(json_log, "a", encoding="utf-8") if json_log else None
        self.pcap_writer = PcapWriter(pcap_output, append=True, sync=True) if pcap_output else None

    def close(self) -> None:
        if self.log_handle:
            self.log_handle.close()
            self.log_handle = None
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None

    def _decode_payload(self, packet: Any) -> Optional[str]:
        if Raw not in packet:
            return None
        payload = bytes(packet[Raw].load)[: self.payload_preview]
        return payload.decode("utf-8", errors="replace").replace("\n", "\\n")

    def _detect_app_proto(self, packet: Any) -> Optional[str]:
        if DNS in packet:
            return "DNS"
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in {80, 8080} or dport in {80, 8080}:
                return "HTTP"
            if sport == 443 or dport == 443:
                return "TLS"
        return None

    def _event_from_packet(self, packet: Any) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "length": len(packet),
            "protocol": "OTHER",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "app_protocol": None,
            "info": None,
            "payload_preview": None,
        }

        if ARP in packet:
            event["protocol"] = "ARP"
            event["src_ip"] = packet[ARP].psrc
            event["dst_ip"] = packet[ARP].pdst
            event["info"] = f"who-has {packet[ARP].pdst} tell {packet[ARP].psrc}"

        elif IP in packet:
            event["src_ip"] = packet[IP].src
            event["dst_ip"] = packet[IP].dst

            if TCP in packet:
                event["protocol"] = "TCP"
                event["src_port"] = int(packet[TCP].sport)
                event["dst_port"] = int(packet[TCP].dport)
                event["info"] = f"flags={packet[TCP].flags} seq={packet[TCP].seq}"
            elif UDP in packet:
                event["protocol"] = "UDP"
                event["src_port"] = int(packet[UDP].sport)
                event["dst_port"] = int(packet[UDP].dport)
            elif ICMP in packet:
                event["protocol"] = "ICMP"
                event["info"] = f"type={packet[ICMP].type} code={packet[ICMP].code}"
            else:
                event["protocol"] = "IP"

        elif IPv6 in packet:
            event["protocol"] = "IPv6"
            event["src_ip"] = packet[IPv6].src
            event["dst_ip"] = packet[IPv6].dst

        event["app_protocol"] = self._detect_app_proto(packet)
        if DNS in packet and packet[DNS].qd:
            qname = packet[DNS].qd.qname
            event["info"] = f"DNS query {qname.decode(errors='ignore').rstrip('.')}"

        if self.verbose:
            event["payload_preview"] = self._decode_payload(packet)

        return event

    def _passes_protocol_filter(self, event: Dict[str, Any]) -> bool:
        selected = self.protocol_filter.lower()
        if selected == "all":
            return True

        proto = str(event.get("protocol", "")).lower()
        app_proto = str(event.get("app_protocol", "")).lower()

        if selected in {"tcp", "udp", "icmp", "arp"}:
            return proto == selected
        if selected in {"dns", "http", "tls"}:
            return app_proto == selected

        return True

    def _print_event(self, event: Dict[str, Any]) -> None:
        src = event.get("src_ip") or "-"
        dst = event.get("dst_ip") or "-"
        sport = event.get("src_port")
        dport = event.get("dst_port")
        ports = ""
        if isinstance(sport, int) and isinstance(dport, int):
            ports = f" {sport}->{dport}"

        app = f" [{event['app_protocol']}]" if event.get("app_protocol") else ""
        info = f" | {event['info']}" if event.get("info") else ""

        print(
            f"{event['timestamp']} | {event['protocol']:<5}{app:<7} | "
            f"{src} -> {dst}{ports} | len={event['length']}{info}"
        )

        if self.verbose and event.get("payload_preview"):
            print(f"  payload: {event['payload_preview']}")

    def _log_event(self, event: Dict[str, Any]) -> None:
        if not self.log_handle:
            return
        self.log_handle.write(json.dumps(event, ensure_ascii=True) + "\n")
        self.log_handle.flush()

    def _packet_handler(self, packet: Any) -> None:
        if self.stopping:
            return

        event = self._event_from_packet(packet)
        if not self._passes_protocol_filter(event):
            return

        self.stats.update(event, len(packet))
        self._print_event(event)
        self._log_event(event)

        if self.pcap_writer:
            self.pcap_writer.write(packet)

    def stop(self, *_args: Any) -> None:
        self.stopping = True

    def _sniff_layer2(self, count: int, timeout: Optional[int]) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._packet_handler,
            store=False,
            count=count if count > 0 else 0,
            timeout=timeout,
            stop_filter=lambda _pkt: self.stopping,
        )

    def _sniff_layer3_fallback(self, count: int, timeout: Optional[int]) -> None:
        print("Falling back to layer-3 capture (BPF filter may be unavailable in this mode).")
        l3_socket = conf.L3socket(iface=self.interface)
        try:
            sniff(
                opened_socket=l3_socket,
                prn=self._packet_handler,
                store=False,
                count=count if count > 0 else 0,
                timeout=timeout,
                stop_filter=lambda _pkt: self.stopping,
            )
        finally:
            l3_socket.close()

    def run(self, count: int, timeout: Optional[int]) -> None:
        print("=" * 90)
        print(f"Interface:        {self.interface}")
        print(f"BPF filter:       {self.bpf_filter or 'none'}")
        print(f"Protocol filter:  {self.protocol_filter}")
        print(f"Verbose payload:  {self.verbose}")
        print("Press Ctrl+C to stop.")
        print("=" * 90)

        signal.signal(signal.SIGINT, self.stop)

        try:
            try:
                self._sniff_layer2(count=count, timeout=timeout)
            except RuntimeError as exc:
                message = str(exc).lower()
                if "winpcap is not installed" in message or "layer 2" in message:
                    print("\nCapture backend error: Npcap/WinPcap is not installed or unavailable.")
                    if sys.platform.startswith("win"):
                        print("Install Npcap from https://npcap.com/#download and enable WinPcap compatibility mode.")
                        print("Then re-run this script in an Administrator terminal.")
                        return
                    try:
                        self._sniff_layer3_fallback(count=count, timeout=timeout)
                    except Exception:
                        print("Install Npcap from https://npcap.com/#download and enable WinPcap compatibility mode.")
                        print("Then re-run this script in an Administrator terminal.")
                        return
                raise
        finally:
            self.close()
            self.stats.print_summary()

    def run_pcap(self, pcap_path: str, count: int) -> None:
        print("=" * 90)
        print(f"Offline source:   {pcap_path}")
        print(f"Protocol filter:  {self.protocol_filter}")
        print(f"Verbose payload:  {self.verbose}")
        print("=" * 90)

        processed = 0
        try:
            with PcapReader(pcap_path) as reader:
                for packet in reader:
                    if self.stopping:
                        break
                    self._packet_handler(packet)
                    processed += 1
                    if count > 0 and processed >= count:
                        break
        except FileNotFoundError:
            print(f"PCAP file not found: {pcap_path}")
        finally:
            self.close()
            self.stats.print_summary()


def _extract_guid(interface_name: str) -> Optional[str]:
    match = re.search(r"\{([0-9A-Fa-f-]+)\}", interface_name)
    if not match:
        return None
    return match.group(1).upper()


def _get_default_route_iface() -> Optional[str]:
    try:
        route = conf.route.route("0.0.0.0")
        if isinstance(route, tuple) and len(route) > 0:
            return str(route[0])
    except Exception:
        return None
    return None


def _build_interface_details(available_ifaces: list[str]) -> list[Dict[str, Any]]:
    details: list[Dict[str, Any]] = []
    default_iface = _get_default_route_iface()

    windows_map: Dict[str, Dict[str, Any]] = {}
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list  # type: ignore

            for item in get_windows_if_list():
                guid = str(item.get("guid", "")).upper()
                if guid:
                    windows_map[guid] = item
        except Exception:
            windows_map = {}

    for idx, iface in enumerate(available_ifaces, start=1):
        guid = _extract_guid(iface)
        win_info = windows_map.get(guid or "", {})
        description = str(win_info.get("description") or "")
        friendly_name = str(win_info.get("name") or "")
        ips = win_info.get("ips") if isinstance(win_info.get("ips"), list) else []

        if not description or not friendly_name:
            try:
                iface_obj = resolve_iface(iface)
                if not description:
                    description = str(getattr(iface_obj, "description", "") or "")
                if not friendly_name:
                    friendly_name = str(getattr(iface_obj, "name", "") or "")
            except Exception:
                pass

        details.append(
            {
                "index": idx,
                "iface": iface,
                "friendly_name": friendly_name,
                "description": description,
                "ips": ips,
                "is_default": iface == default_iface,
            }
        )

    return details


def print_interface_list(available_ifaces: list[str]) -> None:
    details = _build_interface_details(available_ifaces)
    print("Available interfaces:")
    for item in details:
        marker = "*" if item["is_default"] else " "
        print(f"{item['index']:>2}. {marker} {item['iface']}")
        if item["friendly_name"]:
            print(f"    name: {item['friendly_name']}")
        if item["description"]:
            print(f"    desc: {item['description']}")
        if item["ips"]:
            print(f"    ips:  {', '.join(str(ip) for ip in item['ips'])}")
    print("\nLegend: '*' marks the default-route interface (usually active for internet traffic).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Advanced Network Packet Sniffer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    parser.add_argument("interface", nargs="?", help="Network interface to sniff (example: Wi-Fi)")
    parser.add_argument("--iface-index", type=int, default=None, help="Select interface by index from --list-interfaces")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--timeout", type=int, default=None, help="Stop capture after N seconds")
    parser.add_argument("--bpf", default=None, help="BPF filter, e.g. 'tcp and port 80'")
    parser.add_argument("--read-pcap", default=None, help="Read packets from an existing PCAP file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument(
        "--protocol",
        default="all",
        choices=["all", "tcp", "udp", "icmp", "arp", "dns", "http", "tls"],
        help="Protocol/application filter",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show payload preview")
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=80,
        help="Maximum payload bytes to print when verbose mode is enabled",
    )
    parser.add_argument(
        "--json-log",
        default=None,
        help="Path to JSONL log file (one JSON object per packet)",
    )
    parser.add_argument(
        "--pcap-output",
        default=None,
        help="Path to save captured packets in PCAP format",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    available_ifaces = get_if_list()

    if args.iface_index is not None:
        if args.iface_index < 1 or args.iface_index > len(available_ifaces):
            print(f"Error: --iface-index must be between 1 and {len(available_ifaces)}")
            print("Run with --list-interfaces to view valid indices.")
            return
        args.interface = available_ifaces[args.iface_index - 1]

    if args.list_interfaces:
        print_interface_list(available_ifaces)
        return

    if len(sys.argv) == 1:
        print("No arguments supplied.")
        print("Use one of these:")
        print("  1) Live capture:  python network_sniffer.py \"<interface>\"")
        print("  2) Live capture:  python network_sniffer.py --iface-index 1")
        print("  3) Offline mode:  python network_sniffer.py --read-pcap capture.pcap")
        print("  4) List adapters: python network_sniffer.py --list-interfaces")
        print()
        print_interface_list(available_ifaces)
        return

    if not args.interface and not args.read_pcap:
        parser.print_help()
        print("\nError: Provide an interface for live capture or use --read-pcap for offline analysis.")
        return

    if args.interface and not args.read_pcap:
        user_iface = args.interface.strip()
        if user_iface == "<interface>":
            print("Error: replace '<interface>' with a real interface name.")
            print("Example:")
            print("  python network_sniffer.py \"Wi-Fi\" --count 20 --timeout 10")
            print("\nUse --list-interfaces to see valid names on your machine.")
            return

        if user_iface not in available_ifaces:
            print(f"Error: interface not found: {user_iface}")
            close = difflib.get_close_matches(user_iface, available_ifaces, n=3, cutoff=0.2)
            if close:
                print("Did you mean:")
                for item in close:
                    print(f"- {item}")
            else:
                print("Run with --list-interfaces to select a valid interface.")
            return

    sniffer = AdvancedSniffer(
        interface=args.interface or "offline",
        bpf_filter=args.bpf,
        protocol_filter=args.protocol,
        verbose=args.verbose,
        payload_preview=max(1, args.payload_bytes),
        json_log=args.json_log,
        pcap_output=args.pcap_output,
    )

    if args.read_pcap:
        sniffer.run_pcap(pcap_path=args.read_pcap, count=max(0, args.count))
    else:
        sniffer.run(count=max(0, args.count), timeout=args.timeout)


if __name__ == "__main__":
    main()
