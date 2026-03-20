import unittest

import network_sniffer as ns


class NetworkSnifferTests(unittest.TestCase):
    def test_extract_guid(self) -> None:
        iface = r"\\Device\\NPF_{11111111-2222-3333-4444-555555555555}"
        self.assertEqual(ns._extract_guid(iface), "11111111-2222-3333-4444-555555555555")

    def test_extract_guid_missing(self) -> None:
        self.assertIsNone(ns._extract_guid("Wi-Fi"))

    def test_parser_iface_index(self) -> None:
        parser = ns.build_parser()
        args = parser.parse_args(["--iface-index", "3", "--count", "10"])
        self.assertEqual(args.iface_index, 3)
        self.assertEqual(args.count, 10)

    def test_parser_protocol_filter(self) -> None:
        parser = ns.build_parser()
        args = parser.parse_args(["--protocol", "dns", "--timeout", "15", "Wi-Fi"])
        self.assertEqual(args.protocol, "dns")
        self.assertEqual(args.timeout, 15)
        self.assertEqual(args.interface, "Wi-Fi")


if __name__ == "__main__":
    unittest.main()
