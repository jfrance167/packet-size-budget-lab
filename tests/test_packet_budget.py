"""Independent hand oracles, field domains and bounded CLI regressions."""

import copy
import io
import json
from pathlib import Path
import socket
import subprocess  # nosec B404: fixed owned CLI tests, no shell or foreign code.
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import packet_budget as lab

ROOT = Path(__file__).resolve().parents[1]


def case(**changes):
    return {"id": "invented", "context": "unfragmented", "ip_version": 4,
            "ipv4_options_bytes": 0, "ipv6_extensions": [], "transport": "tcp",
            "tcp_options_bytes": 0, "payload_bytes": 1460, "carrier_mtu_bytes": 1500,
            "encapsulation": [], **changes}


def document(cases):
    return json.dumps({"version": 1, "cases": cases}).encode()


def row(**changes):
    return lab.analyze(document([case(**changes)]))["rows"][0]


class BudgetTests(unittest.TestCase):
    def test_frozen_independent_hand_oracles(self):
        oracles = json.loads((ROOT / "tests/hand-oracles.json").read_bytes())
        report = lab.analyze((ROOT / "examples/budgets.json").read_bytes())
        self.assertEqual(len(report["rows"]), 7)
        for value in report["rows"]:
            actual = {k: value["metrics"][k] for k in ("ip_header_bytes", "transport_header_bytes",
                      "inner_packet_bytes", "compared_carrier_bytes", "packet_margin_bytes", "max_payload_bytes")}
            actual.update(ip_field_bytes=value["checks"]["inner_ip_length_field"]["count_bytes"],
                          udp_field_bytes=value["checks"]["udp_length_field"]["count_bytes"]
                          if value["checks"]["udp_length_field"] else None,
                          violated_checks=value["violated_checks"])
            self.assertEqual(actual, oracles[value["id"]], value["id"])

    def test_mtu_equality_one_past(self):
        for payload, fits, margin in ((1459, True, 1), (1460, True, 0), (1461, False, -1)):
            value = row(payload_bytes=payload)
            self.assertEqual(value["checks"]["supplied_mtu"]["fits"], fits)
            self.assertEqual(value["metrics"]["packet_margin_bytes"], margin)
            self.assertEqual(value["status"], "supported")

    def test_negative_and_zero_capacity(self):
        for mtu, maximum, fits in ((39, None, False), (40, 0, True), (41, 1, True)):
            value = row(payload_bytes=0, carrier_mtu_bytes=mtu)
            self.assertEqual(value["metrics"]["max_payload_bytes"], maximum)
            self.assertEqual(value["checks"]["fits_model"], fits)
            self.assertEqual(value["metrics"]["mtu_payload_budget_bytes"], mtu - 40)

    def test_field_ceiling_literal_capacity_matrix(self):
        matrix = [({}, 65495), ({"transport": "udp"}, 65507),
                  ({"ip_version": 6}, 65515), ({"ip_version": 6, "transport": "udp"}, 65527),
                  ({"ipv4_options_bytes": 40, "tcp_options_bytes": 40}, 65415),
                  ({"ip_version": 6, "tcp_options_bytes": 12,
                    "ipv6_extensions": [{"kind": "hop_by_hop", "bytes": 8},
                                        {"kind": "destination", "bytes": 16}]}, 65479)]
        for changes, capacity in matrix:
            for extra in (0, 1):
                value = row(**changes, payload_bytes=capacity + extra, carrier_mtu_bytes=100000)
                self.assertEqual(value["metrics"]["inner_field_payload_capacity_bytes"], capacity)
                self.assertEqual(value["metrics"]["max_payload_bytes"], capacity)
                self.assertEqual(value["checks"]["inner_length_fields_fit"], extra == 0)
                self.assertTrue(value["checks"]["supplied_mtu"]["fits"])

    def test_ipv6_excludes_base_includes_extensions(self):
        value = row(ip_version=6, transport="udp", payload_bytes=100,
                    ipv6_extensions=[{"kind": "hop_by_hop", "bytes": 8}, {"kind": "destination", "bytes": 16}])
        self.assertEqual(value["metrics"]["inner_packet_bytes"], 172)
        self.assertEqual(value["checks"]["inner_ip_length_field"]["count_bytes"], 132)
        self.assertEqual(value["checks"]["udp_length_field"]["count_bytes"], 108)

    def test_independent_failures_and_priority(self):
        value = row(ip_version=6, transport="udp", payload_bytes=65528)
        self.assertEqual(value["violated_checks"], ["ipv6_payload_length", "udp_length", "supplied_carrier_mtu"])
        self.assertFalse(value["checks"]["inner_length_fields_fit"])
        self.assertFalse(value["checks"]["supplied_mtu"]["fits"])
        self.assertFalse(value["checks"]["fits_model"])
        tcp = row(ip_version=6, payload_bytes=65516)
        self.assertIsNone(tcp["checks"]["udp_length_field"])
        self.assertEqual(tcp["violated_checks"], ["ipv6_payload_length", "supplied_carrier_mtu"])

    def test_cost_once_and_no_implicit_headers(self):
        value = row(payload_bytes=100, encapsulation=[{"id": "extra", "bytes": 27}])
        self.assertEqual(value["metrics"]["inner_packet_bytes"], 140)
        self.assertEqual(value["metrics"]["compared_carrier_bytes"], 167)
        self.assertEqual(value["metrics"]["encapsulation_bytes"], 27)
        self.assertEqual(value["metrics"]["max_payload_bytes"], 1433)
        self.assertEqual(value["ledger"][-1], {"component": "encapsulation:extra", "domain": "carrier_extra", "bytes": 27})

    def test_ledger_domains_and_units(self):
        report = lab.analyze((ROOT / "examples/budgets.json").read_bytes())
        self.assertEqual(report["units"], "octets")
        for value in report["rows"]:
            self.assertEqual(sum(item["bytes"] for item in value["ledger"]), value["metrics"]["compared_carrier_bytes"])
            self.assertEqual(sum(item["bytes"] for item in value["ledger"] if item["domain"] == "inner_ip"),
                             value["metrics"]["inner_packet_bytes"])
            self.assertEqual(value["uncertainty"]["scope"], "modeled_inner_fields_and_supplied_carrier_budget")
            self.assertEqual(set(value["uncertainty"].values()), {"unverified", "modeled_inner_fields_and_supplied_carrier_budget"})

    def test_supported_header_combinations(self):
        sequences = ([], [{"kind": "hop_by_hop", "bytes": 8}], [{"kind": "destination", "bytes": 8}],
                     [{"kind": "hop_by_hop", "bytes": 256}, {"kind": "destination", "bytes": 256}])
        for transport in ("tcp", "udp"):
            for extensions in sequences:
                value = row(ip_version=6, transport=transport, ipv6_extensions=extensions, payload_bytes=0)
                self.assertEqual(value["status"], "supported")
        value = row(ip_version=6, tcp_options_bytes=40, ipv6_extensions=sequences[-1], payload_bytes=0,
                    carrier_mtu_bytes=612)
        self.assertEqual(value["metrics"]["ip_header_bytes"], 552)
        self.assertEqual(value["metrics"]["transport_header_bytes"], 60)
        self.assertEqual(value["metrics"]["max_payload_bytes"], 0)

    def test_unsupported_contexts_null_results(self):
        for context in ("fragmentation", "jumbogram", "offload"):
            value = row(context=context, payload_bytes=100000)
            self.assertEqual(value["status"], "unsupported")
            for field in ("metrics", "ledger", "checks", "violated_checks"):
                self.assertIsNone(value[field])
            self.assertEqual(value["assumptions"]["context"], context)
        self.assertEqual(lab.analyze((ROOT / "examples/mixed.json").read_bytes())["status"], "mixed_or_unsupported")

    def test_whole_admission_before_any_calculation(self):
        with patch.object(lab, "_calculate", side_effect=AssertionError("calculation began")):
            for first in (case(), case(context="offload"), case(payload_bytes=100000)):
                with self.assertRaises(lab.LabError):
                    lab.analyze(document([first, case(id="bad", ipv4_options_bytes=1)]))
                with self.assertRaises(lab.LabError):
                    lab.analyze(document([first, case(id="bad", context="unknown")]))
        with self.assertRaises(lab.LabError):
            lab.analyze((ROOT / "examples/invalid-late.json").read_bytes())

    def test_empty_and_order(self):
        result = lab.analyze(document([]))
        self.assertEqual(result["status"], "supported")
        self.assertEqual(result["rows"], [])
        result = lab.analyze(document([case(id="z"), case(id="a")]))
        self.assertEqual([v["id"] for v in result["rows"]], ["z", "a"])

    def test_exact_types_ranges_and_alignment(self):
        bad = [("ip_version", v) for v in (True, 5, "4", [], None)]
        bad += [("ipv4_options_bytes", v) for v in (-4, 1, 44, True)]
        bad += [("tcp_options_bytes", v) for v in (-4, 2, 44, False)]
        bad += [("payload_bytes", v) for v in (-1, 100001, False, "10")]
        bad += [("carrier_mtu_bytes", v) for v in (0, 100001, True)]
        bad += [("id", v) for v in ("-bad", "bad-", "a" * 33, "a_b", "\x1b", "é", 1)]
        bad += [("context", v) for v in ("unknown", {}, 1)] + [("transport", v) for v in ("icmp", {}, 6)]
        for name, value in bad:
            with self.subTest(name=name, value=value), self.assertRaises(lab.LabError):
                row(**{name: value})

    def test_family_transport_extension_mismatch(self):
        for changes in ({"ip_version": 6, "ipv4_options_bytes": 4},
                        {"ipv6_extensions": [{"kind": "destination", "bytes": 8}]},
                        {"transport": "udp", "tcp_options_bytes": 4}):
            with self.assertRaises(lab.LabError):
                row(**changes)
        for extensions in (None, {}, [{"kind": "fragment", "bytes": 8}],
                           [{"kind": "destination", "bytes": v} for v in (8, 8)],
                           [{"kind": "destination", "bytes": 8}, {"kind": "hop_by_hop", "bytes": 8}],
                           [{"kind": "hop_by_hop", "bytes": v} for v in (8, 8, 8)],
                           [{"kind": "destination", "bytes": v} for v in (0, 9, 264)],
                           [{"kind": "destination", "bytes": True}], [{"kind": "destination", "bytes": 8, "x": 1}]):
            with self.assertRaises(lab.LabError):
                row(ip_version=6, ipv6_extensions=extensions)
        for value in (0, 7, 9, 264, True):
            with self.assertRaises(lab.LabError):
                row(ip_version=6, ipv6_extensions=[{"kind": "destination", "bytes": value}])

    def test_extras_shape_range_duplicates(self):
        for extras in (None, {}, [{"id": "a", "bytes": 0}], [{"id": "a", "bytes": 4097}],
                       [{"id": "a", "bytes": True}], [{"id": "a", "bytes": 8}] * 2,
                       [{"id": str(i), "bytes": 1} for i in range(5)],
                       [{"id": "a", "bytes": 8, "protocol": "udp"}], [{"id": "-a", "bytes": 8}]):
            with self.assertRaises(lab.LabError):
                row(encapsulation=extras)
        self.assertEqual(row(encapsulation=[{"id": str(i), "bytes": 4096} for i in range(4)])
                         ["metrics"]["encapsulation_bytes"], 16384)

    def test_schema_unknown_duplicate_and_version(self):
        for root in ({}, [], {"version": True, "cases": []}, {"version": 2, "cases": []},
                     {"version": 1, "cases": {}, "x": 0}, {"version": 1, "cases": None},
                     {"version": 1, "cases": [case(), case()]},
                     {"version": 1, "cases": [{**case(), "x": 1}]}):
            with self.assertRaises(lab.LabError):
                lab.analyze(json.dumps(root).encode())
        broken = case()
        del broken["payload_bytes"]
        with self.assertRaises(lab.LabError):
            lab.analyze(document([broken]))

    def test_api_no_coercion(self):
        class Foreign:
            def __bytes__(self):
                raise AssertionError("coercion")
        class Derived(bytes):
            pass
        for value in (Foreign(), Derived(b"{}"), bytearray(b"{}"), None, "{}"):
            with self.assertRaises(lab.LabError):
                lab.analyze(value)

    def test_json_syntax_and_bounds(self):
        for raw in (b"", b"\xff", b'\xef\xbb\xbf{}', b'{"version":1,"ver\\u0073ion":1}',
                    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'{"x":12345678901}',
                    b'{"x":"\\ud800"}', b'{"x":"\\u001b"}', b'"' + b"a" * 65 + b'"',
                    b"[" * 7 + b"]" * 7, b'{"x":1,}', b"{}{}", b'"unterminated'):
            with self.subTest(raw=raw[:25]), self.assertRaises(lab.LabError):
                lab.analyze(raw)
        base = document([])
        self.assertEqual(lab.analyze(base + b" " * (lab.MAX_INPUT - len(base)))["status"], "supported")
        with self.assertRaises(lab.LabError):
            lab.analyze(base + b" " * (lab.MAX_INPUT + 1 - len(base)))

    def test_case_and_identifier_boundaries(self):
        self.assertEqual(len(lab.analyze(document([case(id=str(i)) for i in range(64)]))["rows"]), 64)
        with self.assertRaises(lab.LabError):
            lab.analyze(document([case(id=str(i)) for i in range(65)]))
        self.assertEqual(row(id="a" * 32, payload_bytes=100000)["status"], "supported")
        self.assertEqual(len(lab.analyze(document([case(id="A"), case(id="a")]))["rows"]), 2)

    def test_no_network_process_and_input_unchanged(self):
        source = document([case()])
        before = copy.copy(source)
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(lab.analyze(source)["status"], "supported")
        self.assertEqual(source, before)

    def test_defensive_output_guard_narrow_seam(self):
        with patch.object(lab, "MAX_OUTPUT", 1), self.assertRaises(lab.LabError):
            row()


class CliTests(unittest.TestCase):
    def command(self, path="-"):
        return [sys.executable, *(["-O"] if sys.flags.optimize else []), str(ROOT / "packet_budget.py"), str(path)]

    def test_cli_statuses_and_no_report_on_invalid(self):
        for name, expected in (("budgets", 0), ("mixed", 3), ("empty", 0), ("invalid-late", 2)):
            child = subprocess.run(self.command(ROOT / "examples" / (name + ".json")),
                                   capture_output=True, timeout=10)  # nosec B603: fixed owned CLI/invented fixture.
            self.assertEqual(child.returncode, expected)
            if expected == 2:
                self.assertEqual(child.stdout, b"")
            else:
                self.assertEqual(json.loads(child.stdout)["version"], 1)

    def test_stdin_and_missing_file(self):
        child = subprocess.run(self.command(), input=document([]), capture_output=True,
                               timeout=10)  # nosec B603: fixed owned CLI, synthetic stdin.
        self.assertEqual(child.returncode, 0)
        child = subprocess.run(self.command(ROOT / "absent.json"), capture_output=True,
                               timeout=10)  # nosec B603: fixed owned CLI, missing owned file.
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stdout, b"")
        self.assertNotIn(b"absent", child.stderr)

    def test_short_flush_and_diagnostic_failures(self):
        class Sink:
            def __init__(self, mode):
                self.mode = mode
            def write(self, data):
                return len(data) - 1 if self.mode == "short" else len(data)
            def flush(self):
                if self.mode == "flush":
                    raise OSError("synthetic flush failure")
        class Diagnostic:
            def write(self, text):
                raise OSError("synthetic diagnostic failure")
        for mode in ("short", "flush"):
            for broken_diagnostic in (False, True):
                with patch.object(sys, "stdout", SimpleNamespace(buffer=Sink(mode))), \
                     patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(document([])))), \
                     patch.object(sys, "stderr", Diagnostic() if broken_diagnostic else io.StringIO()):
                    self.assertEqual(lab.main(["-"]), 2)
                    self.assertIsNone(sys.stdout)
                    if broken_diagnostic:
                        self.assertIsNone(sys.stderr)

    def test_actual_receiving_pipes_closed(self):
        for both in (False, True):
            child = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)  # nosec B603: fixed owned CLI, synthetic stdin.
            try:
                child.stdout.close()
                if both:
                    child.stderr.close()
                child.stdin.write(document([]))
                child.stdin.close()
                self.assertEqual(child.wait(timeout=10), 2)
                if not both:
                    self.assertNotIn(b"Exception ignored", child.stderr.read())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
                child.stderr.close()


if __name__ == "__main__":
    unittest.main()
