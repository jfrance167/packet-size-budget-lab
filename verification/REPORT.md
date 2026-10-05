# Local verification — October 5, 2026

Approved PLAN stages 1–4 complete locally on Windows CPython 3.13.7. Exact-byte
stdlib API/JSON CLI, frozen common contract, seven hand oracles, four examples,
tests/reusable verifier and portfolio/security/learning documentation. No repository.

| Check | Actual outcome |
|---|---|
| Normal unittest | 25 passed; normal.log |
| Optimized unittest/optimized CLI children | 25 passed; optimized.log |
| Frozen contract/oracle fixture hashes | all six unchanged from pre-code receipt |
| Independent hand oracles | seven expected ledgers/sums/counts/fit limits matched |
| Literal field-capacity matrix | six configurations at exact/one-past matched |
| Schema/common admission | exact bounds/types/alignment/family/order/context and invalid-later precedence passed |
| Actual output handling | real closed stdout/both receiving pipes return 2; short/flush/diagnostic mocks pass |
| IPv6 base counted mutation | exit 1, three assertion failures |
| MTU equality rejected mutation | exit 1, three assertion failures |
| Restoration/final verification | exact original source restored; normal/-O/compile/Bandit pass |
| Bandit 1.9.4 app/tests/verifier | zero findings/errors; seven narrow rule exclusions; bandit.json |
| Four demos | budgets 0/seven rows, empty 0, mixed 3/four rows, invalid-late 2/no report |

`receipt.json` binds ten current files: source/tests/verifier/schema/oracles/frozen
receipt and four examples. Application SHA256
`11106527bf932089c9e9a2956693df2476554f00b478c4389f0071fdaeb4837c`.
`frozen-contract.json` records exact six schema/oracle/example hashes BEFORE code;
verifier checks them. Latest-run status distinguishes failed/running checks from a
historical successful receipt. README documents repeatable helper usage/assumptions.

## ECC self-review

Applied installed ecc-code-review pinned checklist and ecc-verification-loop to
actual application, admission, _calculate/analyze/CLI callers, tests, verifier,
frozen examples/schema and docs. Reviewed exact types and bounded JSON, common
compatibility before context dispatch, independent domains/capacity/negative sign,
single-charge ledger, unsupported null rows, deterministic check/status priority,
output delivery and verifier source restoration/cache handling.
Implementing-agent self-review; no independent audit. Zero unresolved confirmed
application defects found. Test review noticed a combined invalid-extension list
hit the two-entry cap before individual size guards; added single-entry exact
bad-size/type cases and ran the final checks. No application behavior change needed.
Output/double-sink shutdown lesson reused from the verified framing lab and real
normal/-O process regressions retained.

Seven narrow explained Bandit rule exclusions: test import B404 and four fixed
test subprocess sites B603; verifier import B404 and fixed Python command B603.
Application has no suppressions. No shell, third-party execution or network access.
Authored task files reviewed for private material/credentials; no dedicated scanner
or history assurance claimed. Parent pre-existing tracked modifications unchanged.

## Bounds and limitations

Defensive output guard tested with MAX_OUTPUT reduced to one byte at a narrow seam.
Under current compact controlled report, a conservative per-row allowance is 3500
bytes: assumptions <=700, ledger <=1000 (max nine entries), metrics <=500, checks
<=500, uncertainty <=350 and row metadata/violation list <=350. Finite numeric
widths and ASCII LDH/controlled strings need no extra escaping. 64×3500+512 envelope
=224512 <262144, so no reachable valid overflow demonstration is claimed.
Largest-shape invented stress (64 IPv6/UDP rows with two 256-byte extensions, four
4096-byte extras, maximum data, MTU one and 32-character labels): input 33111 bytes,
compact report 157796 bytes, one row 2463 bytes. Measurement is one stress case,
not proof of exact maximum; conservative shape reasoning supplies the cap argument.
No payload allocation or packet serialization occurred.

Only Windows 3.13.7 ran. Intended Python 3.11+ support is unverified elsewhere.
Linux/other runtimes/hosted CI/CodeQL/advisory/Scorecard/dedicated secret/history
scanner and independent audit NOT RUN. Fixed logical limits do not enforce hard
wall-time/RSS. Forbidden-capability mocks cover exercised entry points, not a
containment boundary. No actual options/enclosing fields/delivery/path/link-MTU,
MSS/fragmentation/reassembly/protocol-conformance assurance. Earlier labs untouched;
original scanner live Linux SYN remains unrun.
