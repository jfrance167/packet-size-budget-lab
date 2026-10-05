# Supplied IP byte budget v1

Frozen before code under October 5 03:01 approval. PLAN defines exact input grammar,
ranges, units, compatibility, arithmetic and threat exclusions. JSON root exactly
version=integer 1, cases=array 0–64. Unknown version/context is admission error,
never an unsupported model. Exact recognized contexts: unfragmented (supported),
fragmentation, jumbogram, offload (unsupported). Every row's common contract validates
before any calculation; invalid later input yields no report or prefix results.

Report exact root fields: version=1, profile="supplied-ip-byte-budget-v1",
units="octets", status=supported or mixed_or_unsupported, rows. Empty is supported.
Rows preserve input order and have exactly id, context, status, reason, assumptions,
ledger, metrics, checks, violated_checks, uncertainty. assumptions contains the full
validated input case, not inferred state. No input payload bytes or address metadata.

Supported status="supported", reason=null. ledger is ordered {component,domain,bytes}
entries: inner_ip_base, inner_ipv4_options (IPv4 only) or inner_ipv6_hop_by_hop/
inner_ipv6_destination (supplied order), inner_tcp_header or inner_udp_header,
inner_transport_payload, then encapsulation:<id> in supplied order. Domain inner_ip
for all inner bytes and carrier_extra for extras. No implicit cost. Zero inner
options/payload remain visible. Sum inner ledger equals inner_packet_bytes; all
ledger bytes equal compared_carrier_bytes.

metrics exactly: ip_base_bytes, ipv4_options_bytes, ipv6_extension_bytes,
ip_header_bytes, transport_header_bytes, transport_unit_bytes, inner_packet_bytes,
encapsulation_bytes, compared_carrier_bytes, mtu_payload_budget_bytes,
packet_margin_bytes, inner_field_payload_capacity_bytes, max_payload_bytes.
Signed budgets are retained; max_payload=null iff no size including zero fits.
Otherwise max_payload is the min of inner-field and supplied-MTU payload capacities.
No negative wrap/clamp, packet allocation or payload-byte generation.

checks exactly: inner_ip_length_field, udp_length_field, supplied_mtu,
inner_length_fields_fit, fits_model. Each length/MTU check is {domain,count_bytes,
limit_bytes,fits}; inner domain ipv4_total_length or ipv6_payload_length, UDP domain
udp_length, MTU domain supplied_carrier_mtu. UDP check=null for TCP. Limit=65535 for
modeled fields, supplied carrier_mtu_bytes for MTU. fits is count <= limit, equality
included. fits_model requires every modeled inner field and supplied MTU check.
Each max-payload/fit result is only this model's declared budget, never validation
of enclosing headers, real transport/path/link compliance or negotiated TCP MSS.

violated_checks lists domains with fits=false in deterministic order:
ipv4_total_length OR ipv6_payload_length, udp_length if applicable, supplied_carrier_mtu.
Evaluate/report every modeled check independently. Supported over-budget rows still
have status supported and CLI status 0.

uncertainty exactly: scope="modeled_inner_fields_and_supplied_carrier_budget",
actual_delivery, path_mtu, outer_field_validity, option_content_validity,
link_minimum_mtu_conformance (all five="unverified"). Present on every row.
Unsupported status="unsupported", reason="context requires rules outside this model",
assumptions preserved; ledger, metrics, checks and violated_checks ALL null. No
arithmetic/fit claim. Mixed top status if any unsupported, not based on budget fit.

CLI 0 all supported (empty included), 3 any unsupported, 2 admission/input/output
error. CLI file or - stdin; bounded read; report encoded before return/write.
Delivery is nontransactional and may leave partial output, but short/flush/closed
output/failed diagnostics must not claim success or replace exit 2 at shutdown.

Public API exact built-in bytes only. Bounded JSON syntax remains json.loads authority;
depth preflight is a resource guard. Unknown/duplicate fields/IDs, bool-as-int,
floating/constants and malformed/oversize strings/numbers/containers invalid.
Neither unsupported context nor an earlier field/MTU failure masks bad later input.
