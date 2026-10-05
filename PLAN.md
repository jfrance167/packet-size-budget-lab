# Packet-size budget lab — proposed plan

October 5, 2026. **Stages 1–4 approved at the coordinator's 03:01 checkpoint.**
Tier 3 portfolio workflow, narrow arithmetic scope. Authorization: coordinator
SUCCESSORS.md 02:41 successor decision under Jake's direct overnight delegation.
Same sole writer chat `01a10a3b-a383-7ee2-a193-8afb04ddba29`; separate directory.
No new scope after October 6, 08:00 Eastern. Preserve all prior labs/shared/parent work.

## Problem, success and recommendation

Given invented IP/transport header sizes, payload size, extra encapsulation bytes
and an explicitly supplied MTU, explain whether their declared byte budget fits.
Avoid confusing transport payload with a complete IP packet, IPv6 Payload Length
with IPv4 Total Length, or a mathematical fit with actual network delivery.

Success: independently hand-calculated outcomes at equality/one-past, clear signed
remaining budget, length-field checks and inert reports with all assumptions visible.
Recommend BUILD an original Python 3.11+ standard-library API/JSON CLI. Reuse reviewed
bounded JSON admission and output-failure handling from the MIT framing/route labs;
no dpkt/React/runtime dependency or borrowed upstream implementation. Research in
RESEARCH.md compared actual sources, tests/CI, licenses, maintenance and dependencies.

Alternative: fragmentation arithmetic could teach eight-octet offset blocks and
different IPv4/IPv6 roles. It adds copied-option, per-fragment header, first-fragment,
alignment and policy assumptions. Defer fragmentation/reassembly; neither a fit nor
an over-budget result here predicts fragmentation, loss, delivery or path MTU.

## Proposed exact input and supported combinations

Public `analyze(data: exact bytes) -> dict`, reject foreign objects/subclasses before
coercion. One UTF-8 JSON file/stdin, JSON report stdout. Root exactly version=1 and
cases (0–64 entries). Each case exactly:

`id`, `context`, `ip_version`, `ipv4_options_bytes`, `ipv6_extensions`, `transport`,
`tcp_options_bytes`, `payload_bytes`, `carrier_mtu_bytes`, `encapsulation`.

- id: unique case-sensitive ASCII LDH label, 1–32 characters, alphanumeric ends.
- context: unfragmented is supported. Recognized fragmentation, jumbogram and
  offload contexts return unsupported rows with null derived values. Unknown invalid.
  Contexts describe requested analysis assumptions, not observed packet metadata.
- ip_version exact integer 4 or 6, never boolean.
- IPv4 options: padded total option bytes 0–40, multiple of four. IPv4 requires
  ipv6_extensions=[]; IPv6 requires ipv4_options_bytes=0.
- IPv6 extensions: at most two objects exactly {kind,bytes}; kind hop_by_hop or
  destination. Whole header bytes 8–256, multiple of eight. Supported sequences
  [], [hop_by_hop], [destination], [hop_by_hop,destination], no repeats/reversal.
  This is a declared teaching subset, not a universal validity rule. No Routing,
  Fragment, AH/ESP, Jumbo option or option-content parsing. Byte counts are assertions.
- transport tcp or udp; TCP padded option bytes 0–40, multiple of four; UDP requires
  tcp_options_bytes=0 and uses its fixed eight-byte header.
- payload_bytes exact integer 0–100000, counting transport data only; no byte payload.
- carrier_mtu_bytes exact integer 1–100000, supplied maximum size of the compared
  complete IP packet. No inferred interface/path/link MTU or minimum-MTU conformance.
- encapsulation: 0–4 objects exactly {id,bytes}, unique LDH ids within the case,
  bytes exact integer 1–4096. These are fixed extra bytes INSIDE the compared carrier
  IP packet, OUTSIDE the complete inner IP packet; include any declared enclosing
  IP/UDP/shim/inner-L2 costs once. Exclude outer Ethernet header/FCS/preamble/interframe
  gap because an IP MTU does not count those. No named tunnel presets, nested outer
  protocol parsing, dynamic encryption padding or verified outer field lengths.

Whole syntactic/structural/semantic admission of every case precedes calculating any
row or unsupported decision. Malformed later cases invalidate the whole document.
Unsupported contexts still validate the common fields/combinations above; they do
not create a relaxed numeric/header grammar. Duplicate case/component IDs invalid.

Bounds: 64 KiB raw input; nesting six; numeric token ten characters, integers only;
decoded strings 64 characters, ASCII identifiers/enums and no controls/surrogates;
no duplicate decoded JSON keys, invalid UTF-8, floats/nonfinite constants, unknown
fields, boolean integers or custom object coercion. Compact encoded report including
newline capped at 256 KiB before return/write. Limits bound logical workload, not
hard process wall-time/RSS or containment.

## Arithmetic and report semantics to freeze before code

All quantities count octets (eight-bit bytes). Let O4=IPv4 option bytes,
E=sum of declared IPv6 whole extension-header bytes, T=transport header bytes,
P=transport payload, C=sum of fixed encapsulation bytes, M=supplied carrier MTU.

IP header H=20+O4 (IPv4), or 40+E (IPv6). T=20+TCP padded option bytes, or 8 (UDP).
Transport unit=T+P; inner complete IP packet=H+T+P; compared carrier size=H+T+P+C.
IPv4 length field counts inner complete packet; IPv6 length field counts E+T+P,
excluding the fixed 40-byte base. UDP length counts 8+P, excluding IP/extensions.
Each modeled length field fits iff its count <=65535; no jumbo/zero-length escape.
TCP has no analogous standalone 16-bit Total Length field; its bound comes from IP.
Unmodeled enclosing length fields/option contents remain unverified.

Signed MTU payload budget M-H-T-C; signed packet margin M-(H+T+P+C). Keep negative
numbers visible; do not clamp to zero and imply a zero-payload packet fits.
Inner field payload capacity: IPv4 65535-H-T; IPv6 65535-E-T, further min with
65535-8 for UDP. max_payload_bytes is min(MTU budget, inner field capacity) when
nonnegative, otherwise null (no payload size, even zero, fits). This quantity is a
declared single-packet data budget, NOT negotiated TCP MSS/application record size.

Per supported row report supplied assumptions, a component byte ledger, all sums,
signed budgets/margin, modeled length-field counts/fits, max_payload_bytes,
fits_supplied_mtu, inner_length_fields_fit, fits_model=both, and all violated checks
in fixed order IPv4/IPv6 length, UDP length, supplied MTU. Preserve independent
checks rather than hiding an over-MTU result behind a field overflow. Mark
actual_delivery, path_mtu, outer_field_validity, option_content_validity and
link_minimum_mtu_conformance unverified. Supported mathematical over-budget rows
are normal results, not invalid inputs or unsupported contexts.

Unsupported rows have context/reason/supplied assumptions, null derived arithmetic
and no fits claim. Top-level report profile `supplied-ip-byte-budget-v1`, version 1,
rows in supplied order; status supported if all supported, otherwise mixed_or_unsupported
(empty list supported). CLI 0 all supported, 3 any unsupported, 2 admission/I/O/output
failure. Short writes, flush/closed output and failed diagnostic must return 2;
partial output can remain on delivery failure. Exact report field names frozen in
SCHEMA during stage 1 before code.

## Independent hand oracles

| Declared case | Expected arithmetic |
|---|---|
| IPv4 TCP, no options/extras, M=1500 P=1460 | H=20 T=20, inner/carrier=1500, margin 0, max payload 1460, fits |
| IPv6 TCP, no extensions/extras, M=1500 P=1460 | H=40 T=20, inner/carrier=1520, IPv6 length=1480, margin -20, max payload 1440, over MTU |
| IPv6 UDP, one 8-byte destination header, M=1280 P=1224 | H=48 T=8, IPv6 length=1240, UDP length=1232, packet=1280, fits |
| IPv4 TCP, no options, extras 20+8+8+14, M=1500 P=1410 | C=50, inner=1450, carrier=1500, max payload 1410; includes inner L2, no outer L2 |
| IPv4 UDP, no options/extras, M=20 P=0 | inner=28, budget/margin -8, max payload null, no payload fits |
| IPv4 UDP, M=100000 P=65508 | inner=65536, UDP=65516, MTU fits but IPv4 field does not; max payload 65507 |
| IPv6 UDP, no extensions, M=100000 P=65527 | IPv6 and UDP length=65535, inner=65575, fits; next payload octet violates both fields |

These are inferred arithmetic under the proposed contract, not measured packet output.

## Threat model, stages and done criteria

Hostile JSON may exploit recursion/numeric/container costs or inject misleading
labels/results. Wrong layers, double-charged headers, IPv6 base miscount, signed
budget clamping and invalid-late-input masking are principal correctness hazards.
Bounded whole admission, exact integers, controlled labels, explicit units/ledgers,
independent hand oracles and inert JSON mitigate them; parser/downstream defects
remain possible. No packets/captures/sockets/probes/process/payload execution,
path-MTU discovery, fragment generation/reassembly, network/device settings,
real operational data, named tunnel recommendations or additional spending.

1. Freeze SCHEMA/report fields/statuses and independent invented JSON fixtures with
   hand oracles/hashes; explain layers and length domains before implementing.
2. Implement bounded admission, pure integer ledger/comparisons and inert API/CLI.
   Reuse reviewed local patterns with MIT attribution; no dependencies/repository.
3. Focused normal/-O tests for equality/one-past, options/header alignment/compatibility,
   negative budget and zero payload, IPv4/IPv6/UDP field ceilings, exactly-once extras,
   invalid/unsupported precedence, all schema limits and forbidden capabilities.
   Two meaningful assertion-detected restored mutations: count IPv6 fixed base in its
   Payload Length, and change MTU <= to <. Actual short/flush/closed stdout/diagnostic
   checks, compile/Bandit through existing tooling. Output cap reachability assessed;
   unreachable cap tested only at narrow guard, never a fabricated overflow demo.
4. ECC actual-code self-review/fixes and affected reruns; README/MIT/SECURITY, STATE,
   DECISIONS, LEARNING, reproducible verifier and exact receipt/results; permitted
   Obsidian milestone. No independent audit/Linux/other-runtime/hosted claim unless run.

Research-at-approval baseline: reviewed local extraction/research, no code/tests or
candidate execution. Implementation proceeds under recorded 03:01 addendum.
