# Learning

Different length fields count different layers. IPv4 Total Length includes the IP
header, IPv6 Payload Length excludes only the fixed base, and UDP Length excludes
all IP headers. A data budget is not the same as an entire packet or negotiated MSS.

The ledger separates inner bytes from extra carrier bytes. A supplied encapsulation
sum says what costs the analyst counted; adding implicit headers would double charge
them. Outer Ethernet is outside an IP MTU, while an explicitly declared inner L2
header inside a tunnel can consume carrier bytes. The model does not verify that
the supplied costs describe any actual tunnel.

MTU equality fits. A negative data budget means even zero data does not fit; preserving
the sign and returning null maximum avoids implying otherwise. Field overflow can
occur even when the supplied MTU is large; report both predicates independently.

Common admission always completes first. A malformed later row cannot be hidden by
an earlier rich context or oversized modeled packet. Unsupported is a legitimate
request outside this model, not a syntax/type/compatibility waiver.

Hand oracles were hashed before code. Mutation checks deliberately include IPv6
base in Payload Length and reject equality, proving expected-value assertions detect
those mistakes rather than merely exercising lines. Bandit passing is separate from
the arithmetic and test evidence. Self-review is not independent audit.

Optional exercise: compare IPv4 UDP and IPv6 UDP at data size 65527. Explain why the
same UDP field ceiling does not give them the same complete-IP-packet ceiling.
