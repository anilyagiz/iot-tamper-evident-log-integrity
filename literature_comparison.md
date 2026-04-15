# Literature Comparison (for Computers & Security Submission)

## Scope
This comparison positions our Merkle-based IoT log integrity system against representative secure-logging and auditability literature.

## Representative Works

1. Schneier & Kelsey (1999), secure audit logs with forward integrity
2. Ma & Tsudik (2009), forward-secure aggregate-authentication logging
3. Crosby & Wallach (2009), efficient tamper-evident logging structures
4. Putz et al. (2019), permissioned-blockchain secure logging infrastructure
5. Ahmad et al. (2019), BlockAudit blockchain-based transparent audit logs
6. RFC 9162 (2021), Certificate Transparency v2 Merkle proof system

## Comparison Summary

- Trust assumptions:
  - Prior blockchain systems: distributed consensus and network trust assumptions.
  - Our system: local Merkle commitments + trusted root anchor (no blockchain requirement).
- Operational overhead:
  - Blockchain systems add consensus and replication latency.
  - Our system keeps ingestion/verification local and lightweight.
- Proof model:
  - Our method uses standard logarithmic inclusion proofs consistent with transparency-log design principles.
- Edge suitability:
  - Our implementation avoids external consensus and is easier to deploy on constrained/edge environments.

## Links

- Schneier & Kelsey 1999: https://dl.acm.org/doi/10.1145/317087.317089
- Ma & Tsudik 2009: https://dl.acm.org/doi/10.1145/1502777.1502779
- Crosby & Wallach 2009 (USENIX): https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf
- Putz et al. 2019: https://doi.org/10.1016/j.cose.2019.101602
- Ahmad et al. 2019: https://doi.org/10.1016/j.jnca.2019.102406
- RFC 9162: https://www.rfc-editor.org/info/rfc9162
