# Packet-budget research — October 5, 2026

Recommendation BUILD original bounded Python stdlib integer model in PLAN.md.
No suitable inspected candidate meets the exact layer/uncertainty/admission contract
unchanged. Targeted research, not exhaustive comparison or security certification.

## Primary sources and fragmentation alternative

- [RFC 791 §3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1): IPv4 IHL
  counts 32-bit words with minimum five; Total Length includes header and data and
  has a 65535-octet ceiling. §3.2 fragmentation uses eight-octet offset blocks,
  differing option-copy behavior and DF constraints; not a single subtraction.
- [RFC 8200 §§3–4](https://www.rfc-editor.org/rfc/rfc8200.html): IPv6 base is 40
  bytes; Payload Length excludes that base and includes extension headers. Hop-by-Hop
  must immediately follow base; proposed ordered subset is narrower than full
  receiver behavior. §4.5 source-only fragmentation differs from IPv4; §5 link
  minimum 1280 does not prove a supplied encapsulated inner budget is an actual link.
- [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html): UDP Length includes its
  eight-byte header and data, excluding IP. Non-jumbo field is 16 bits.
- [RFC 9293 §§3.1,3.7.1](https://datatracker.ietf.org/doc/html/rfc9293): TCP Data
  Offset counts 32-bit words; fixed header 20 bytes and padded options affect the
  actual single-segment data budget. MSS negotiation/effective sending rules involve
  additional conditions; do not label the model's subtraction negotiated MSS.

The proposed math/hand oracles are inferences from declared inputs and field
definitions. No packet generation, serialization oracle or transport conformance test.
An advanced fragmentation model adds option copies, per-fragment headers/alignment,
IPv6 first-fragment constraints and policy state. Defer it rather than infer it from
fits/exceeds. Path MTU, delivery, offloads and tunnel padding are unverified.

## Reuse and strongest candidates: actual inspected artifacts

Local network-forensics-pcap-lab README and pcap_forensics.py `_parse_frame` inspected:
explicit Ethernet start=14; IPv4 IHL*4, total length, TCP offset*4, UDP length>=8.
Useful layer-counting precedent, but reads captures and has no supplied MTU calculator;
do not expand/run it. wireshark-traffic-analysis README describes real capture workflow,
not arithmetic reuse; no raw capture read. Targeted README/source and vault term
searches found no matching model, not an exhaustive inventory. Prior route/framing
notes maintain unknown forwarding/transport; framing explicitly defers MTU arithmetic.
Reuse our MIT bounded admission/output patterns after source review, not old capture
capabilities. Parent tracked modifications seen initially remain untouched.

Connected GitHub search `mtu mss calculator` returned gmowses/mtu-calculator and
gmowses/pppoe-calculator. Inspected the direct calculator at tree/commit
`1d1e36cc519768ef035b0e0f63a613904b8beed3`:
- [Actual source](https://github.com/gmowses/mtu-calculator/blob/1d1e36cc519768ef035b0e0f63a613904b8beed3/src/MtuCalculator.tsx)
  blob `1c1c5064d3043354dac1084d9a198d143b9d1929`; inspected lines 1–240 including
  preset overhead table and effectiveMtu=baseMtu-totalOverhead, mss=effectiveMtu-40.
  Fixed IPv4/no-option MSS arithmetic, named/static tunnel costs and no length-field
  validity meet a different scope. VXLAN note labels 14 bytes outer Ethernet while
  the base input is called physical-interface MTU: layer semantics need explicit
  separation. Static ESP/OpenVPN costs do not establish data-dependent padding.
  These are source-based fit concerns, not executed vulnerability findings.
- [README](https://github.com/gmowses/mtu-calculator/blob/1d1e36cc519768ef035b0e0f63a613904b8beed3/README.md)
  actually describes Password Generator; mismatch reduces documentation confidence.
- [MIT license](https://github.com/gmowses/mtu-calculator/blob/1d1e36cc519768ef035b0e0f63a613904b8beed3/LICENSE)
  blob `c836787036091ca62927bbf5c5f31242c821b823` inspected: preserve copyright/license
  for copied substantial source. No code adopted.
- [package.json](https://github.com/gmowses/mtu-calculator/blob/1d1e36cc519768ef035b0e0f63a613904b8beed3/package.json)
  blob `13c5d6db0d3fc9d20439f2a5bbc05ca7a0066da9`, React/react-dom runtime and Vite,
  TypeScript/Tailwind/lint tooling; UI unnecessary. Recursive tree returned
  truncated=false, no test/spec paths; no test script in inspected metadata.
  [CI](https://github.com/gmowses/mtu-calculator/blob/1d1e36cc519768ef035b0e0f63a613904b8beed3/.github/workflows/ci.yml)
  blob `e2395059da5a9e209ac48ec23409358c270ccec0`: PR npm ci/build only, mutable v4
  action tags, not Jake's SHA baseline. Latest commit April 3, 2026 adds automation;
  maintenance evidence, no hosted pass. Focused MTU issue search empty, not proof
  of no defects. Do not fork/install for this lab.

Established parser reference dpkt at `4f8958eb4b375b38d0ab6ffadf2da9b24395394d`:
- [IPv4 source and tests](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/dpkt/ip.py)
  blob `a9b255e54631f1176e84e00938cf430fc723a33a`; __len__ sums base/options/data,
  serialize/checksum path and header constants read; in-file test_opt/test_iplen/
  constructor/fragment fields tests inspected lines 390–555. Broad packet creation/
  parsing/checksums are outside the proposed arithmetic contract.
- [IPv6 source and tests](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/dpkt/ip6.py)
  blob `e91a235e82c83fdeb1c2f29613c94402d8fdce0b`; plen excludes base, __len__ adds
  retained extension headers; comments distinguish dict versus ordered duplicate
  extension storage. Actual routing/options/fragment and extension-length tests
  inspected lines 300–430, not run. [UDP layout](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/dpkt/udp.py)
  blob `559193c12a4174eaaa4149189a04f47c97d9b895`: eight-byte header/16-bit ulen.
- [BSD-3-Clause license](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/LICENSE)
  blob `99d14371e1e1dc92c281081d590c0ac81e5ef04f`: source/binary notices retained,
  no endorsement. [setup.py](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/setup.py)
  blob `ece4577a27b2332f12e1f94f143e5d876fc62406`: no declared runtime requirements;
  setuptools/distutils build and tests separate. Fewer dependencies do not certify it.
- [CI](https://github.com/kbandla/dpkt/blob/4f8958eb4b375b38d0ab6ffadf2da9b24395394d/.github/workflows/python-package.yml)
  blob `d3f9b1a8f9c8bd19471884f11760ad8fa382e370`: pytest/coverage/lint old Python
  matrix through 3.9, old Ubuntu and mutable actions incl develop. Existing CodeQL
  file listed, not scanned as assurance. Latest returned commit May 5, 2024 is docs
  rendering maintenance; compatibility/current security not verified. Issues #321
  UDP automatic length and unrelated #669 HTTP2 padding were reporter claims, not
  reproduced defects. Not adopting packet serialization avoids scope expansion.

No candidate installed/run, advisory/Scorecard assessment, hosted CI result or
security certification. One incorrect CI filename returned 404 and one IPv6 test
fetch failed; later correct bounded pinned reads supplied actual evidence. Official
RFC9293 endpoint find failed once; IETF datatracker supplied the required header text.
No failure counted as inspection. Connected GitHub available; Firecrawl readiness
unverified, so official browsing used without claiming Firecrawl execution.

## Worker/knowledge choices

Read shared STARTUP/routing references. Existing shared remote readiness was degraded;
no remote draft was necessary, so no refresh/probe/configuration change. Explicitly
considered OpenRouter, retained local-only extraction because qwen3.5:2b returned all
four supplied labels correctly in 541 ms, 25 output tokens, done_reason stop. Raw
brief/draft/metadata preserved. Accepted labels only; Codex reviewed arithmetic/source
and security judgments. No measured savings/general competence claim, extra spending
or remote inference. Laya classification/triage schema unrelated.

Read vault Home/Codex Integration earlier in this continuing task and relevant
framing/route notes; targeted MTU/MSS searches found framing's deferral, no verified
matching calculator. Knowledge milestone prepared after plan completion. At this
research milestone implementation/testing had not begun. The coordinator subsequently
approved stages 1–4 at 03:01 October 5; implementation and local verification are
complete. STATE.md and verification/REPORT.md record current results and limits.
