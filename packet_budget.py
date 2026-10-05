"""Offline supplied IP byte budgets; exact teaching contract in SCHEMA.md."""

from __future__ import annotations

import argparse
import json
import re
import sys

MAX_INPUT = 65536
MAX_OUTPUT = 262144
CONTEXTS = ("unfragmented", "fragmentation", "jumbogram", "offload")
CASE_FIELDS = {"id", "context", "ip_version", "ipv4_options_bytes", "ipv6_extensions",
               "transport", "tcp_options_bytes", "payload_bytes", "carrier_mtu_bytes", "encapsulation"}


class LabError(ValueError):
    """Invalid input representation or failed report delivery."""


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise LabError("duplicate JSON key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > 10:
        raise LabError("numeric token exceeds 10 characters")
    return int(token)


def _noninteger(token: str) -> None:
    raise LabError("non-integer numbers/constants unsupported")


def _strings(value: object) -> None:
    if isinstance(value, str):
        if len(value) > 64 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise LabError("string exceeds 64 characters or contains non-printable/non-ASCII characters")
    elif isinstance(value, dict):
        for key, child in value.items():
            _strings(key)
            _strings(child)
    elif isinstance(value, list):
        for child in value:
            _strings(child)


def _load(data: bytes) -> object:
    # Adapted from Jake's MIT framing/route labs. Preflight bounds depth only;
    # json.loads remains the grammar authority, including brackets/escape syntax.
    if type(data) is not bytes or len(data) > MAX_INPUT:
        raise LabError("input must be exact bytes within 65536 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise LabError("input must be UTF-8") from exc
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 6:
                raise LabError("JSON nesting exceeds 6")
        elif char in "]}":
            depth -= 1
    try:
        root = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_noninteger, parse_constant=_noninteger)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LabError("invalid JSON") from exc
    _strings(root)
    return root


def _fields(value: object, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        raise LabError("invalid, unknown or missing fields")
    return value


def _number(value: object, low: int, high: int, step: int = 1) -> int:
    if type(value) is not int or not low <= value <= high or value % step:
        raise LabError("integer out of range or alignment")
    return value


def _enum(value: object, choices: tuple[str, ...]) -> str:
    if type(value) is not str or value not in choices:
        raise LabError("unknown enum value")
    return value


def _label(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?", value):
        raise LabError("invalid fictional label")
    return value


def _case(raw: object) -> dict:
    case = _fields(raw, CASE_FIELDS)
    _label(case["id"])
    _enum(case["context"], CONTEXTS)
    version = _number(case["ip_version"], 4, 6)
    if version not in (4, 6):
        raise LabError("ip_version must be 4 or 6")
    options = _number(case["ipv4_options_bytes"], 0, 40, 4)
    transport = _enum(case["transport"], ("tcp", "udp"))
    tcp_options = _number(case["tcp_options_bytes"], 0, 40, 4)
    if transport == "udp" and tcp_options:
        raise LabError("UDP cannot declare TCP options")
    _number(case["payload_bytes"], 0, 100000)
    _number(case["carrier_mtu_bytes"], 1, 100000)
    extensions = case["ipv6_extensions"]
    if type(extensions) is not list or len(extensions) > 2:
        raise LabError("extension array exceeds two entries or wrong type")
    kinds = []
    for raw_extension in extensions:
        extension = _fields(raw_extension, {"kind", "bytes"})
        kinds.append(_enum(extension["kind"], ("hop_by_hop", "destination")))
        _number(extension["bytes"], 8, 256, 8)
    if kinds not in ([], ["hop_by_hop"], ["destination"], ["hop_by_hop", "destination"]):
        raise LabError("unsupported extension sequence in common contract")
    if (version == 4 and extensions) or (version == 6 and options):
        raise LabError("IP option/extension family mismatch")
    extras = case["encapsulation"]
    if type(extras) is not list or len(extras) > 4:
        raise LabError("encapsulation array exceeds four entries or wrong type")
    ids = set()
    for raw_extra in extras:
        extra = _fields(raw_extra, {"id", "bytes"})
        label = _label(extra["id"])
        if label in ids:
            raise LabError("duplicate encapsulation id")
        ids.add(label)
        _number(extra["bytes"], 1, 4096)
    return case


def _validate(root: object) -> list[dict]:
    root = _fields(root, {"version", "cases"})
    if type(root["version"]) is not int or root["version"] != 1:
        raise LabError("unknown schema version")
    if type(root["cases"]) is not list or len(root["cases"]) > 64:
        raise LabError("cases must be array within 64 entries")
    cases = [_case(raw) for raw in root["cases"]]
    if len({case["id"] for case in cases}) != len(cases):
        raise LabError("duplicate case id")
    return cases


def _check(domain: str, count: int, limit: int, fits: bool) -> dict:
    return {"domain": domain, "count_bytes": count, "limit_bytes": limit, "fits": fits}


def _calculate(case: dict) -> dict:
    uncertainty = {"scope": "modeled_inner_fields_and_supplied_carrier_budget",
                   **dict.fromkeys(("actual_delivery", "path_mtu", "outer_field_validity",
                                    "option_content_validity", "link_minimum_mtu_conformance"), "unverified")}
    row = {"id": case["id"], "context": case["context"], "status": "unsupported",
           "reason": "context requires rules outside this model", "assumptions": case,
           "ledger": None, "metrics": None, "checks": None, "violated_checks": None,
           "uncertainty": uncertainty}
    if case["context"] != "unfragmented":
        return row
    base = 20 if case["ip_version"] == 4 else 40
    extensions = sum(item["bytes"] for item in case["ipv6_extensions"])
    ip_header = base + case["ipv4_options_bytes"] + extensions
    transport_header = 20 + case["tcp_options_bytes"] if case["transport"] == "tcp" else 8
    payload = case["payload_bytes"]
    transport_unit = transport_header + payload
    inner = ip_header + transport_unit
    extra = sum(item["bytes"] for item in case["encapsulation"])
    compared = inner + extra
    # IPv6 Payload Length excludes ONLY the fixed base, not extension headers.
    ip_count = inner if case["ip_version"] == 4 else extensions + transport_unit
    ip_fits = ip_count <= 65535
    udp_fits = transport_unit <= 65535
    mtu_fits = compared <= case["carrier_mtu_bytes"]
    ip_check = _check("ipv4_total_length" if case["ip_version"] == 4 else "ipv6_payload_length",
                      ip_count, 65535, ip_fits)
    udp_check = _check("udp_length", transport_unit, 65535, udp_fits) if case["transport"] == "udp" else None
    mtu_check = _check("supplied_carrier_mtu", compared, case["carrier_mtu_bytes"], mtu_fits)
    capacity = 65535 - (ip_count - payload)
    if udp_check is not None:
        capacity = min(capacity, 65535 - 8)
    budget = case["carrier_mtu_bytes"] - ip_header - transport_header - extra
    maximum = min(budget, capacity)
    ledger = [{"component": "inner_ip_base", "domain": "inner_ip", "bytes": base}]
    if case["ip_version"] == 4:
        ledger.append({"component": "inner_ipv4_options", "domain": "inner_ip", "bytes": case["ipv4_options_bytes"]})
    else:
        ledger.extend({"component": "inner_ipv6_" + item["kind"], "domain": "inner_ip", "bytes": item["bytes"]}
                      for item in case["ipv6_extensions"])
    ledger.extend(({"component": "inner_" + case["transport"] + "_header", "domain": "inner_ip", "bytes": transport_header},
                   {"component": "inner_transport_payload", "domain": "inner_ip", "bytes": payload}))
    ledger.extend({"component": "encapsulation:" + item["id"], "domain": "carrier_extra", "bytes": item["bytes"]}
                  for item in case["encapsulation"])
    field_fit = ip_fits and (udp_fits if udp_check is not None else True)
    row.update(status="supported", reason=None, ledger=ledger,
               metrics={"ip_base_bytes": base, "ipv4_options_bytes": case["ipv4_options_bytes"],
                        "ipv6_extension_bytes": extensions, "ip_header_bytes": ip_header,
                        "transport_header_bytes": transport_header, "transport_unit_bytes": transport_unit,
                        "inner_packet_bytes": inner, "encapsulation_bytes": extra,
                        "compared_carrier_bytes": compared, "mtu_payload_budget_bytes": budget,
                        "packet_margin_bytes": case["carrier_mtu_bytes"] - compared,
                        "inner_field_payload_capacity_bytes": capacity,
                        "max_payload_bytes": maximum if maximum >= 0 else None},
               checks={"inner_ip_length_field": ip_check, "udp_length_field": udp_check,
                       "supplied_mtu": mtu_check, "inner_length_fields_fit": field_fit,
                       "fits_model": field_fit and mtu_fits},
               violated_checks=[item["domain"] for item in (ip_check, udp_check, mtu_check)
                                if item is not None and not item["fits"]])
    return row


def _encode(report: dict) -> bytes:
    encoded = (json.dumps(report, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT:
        raise LabError("serialized output exceeds 262144 bytes")
    return encoded


def analyze(data: bytes) -> dict:
    """Validate exact JSON bytes and return supplied-budget arithmetic.

    Raises LabError before any report on admission/output-limit failure. Recognized
    unsupported contexts return null-derived rows. Fits never establishes actual
    delivery, enclosing field validity, option content or negotiated TCP MSS.
    """
    cases = _validate(_load(data))
    rows = [_calculate(case) for case in cases]
    report = {"version": 1, "profile": "supplied-ip-byte-budget-v1", "units": "octets",
              "status": "mixed_or_unsupported" if any(row["status"] == "unsupported" for row in rows) else "supported",
              "rows": rows}
    _encode(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="invented-count JSON file, or - for stdin")
    args = parser.parse_args(argv)
    writing = False
    try:
        if args.scenario == "-":
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
        else:
            with open(args.scenario, "rb") as stream:
                data = stream.read(MAX_INPUT + 1)
        report = analyze(data)
        output = _encode(report)
        writing = True
        if sys.stdout.buffer.write(output) != len(output):
            raise LabError("short output write")
        sys.stdout.buffer.flush()
        return 3 if report["status"] == "mixed_or_unsupported" else 0
    except (LabError, OSError) as exc:
        if writing:
            # Prevent CPython shutdown flush retry from replacing exit 2 with 120.
            sys.stdout = None
        message = str(exc) if isinstance(exc, LabError) else "input/output operation failed"
        try:
            print("packet-budget: " + message, file=sys.stderr)
        except OSError:
            sys.stderr = None
            return 2
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
