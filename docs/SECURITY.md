# SECURITY.md

## Security Policy

`kanidm_radsec_edge` is a security-focused **RadSec edge service** for **EAP-TLS-only** environments and is intended to front a **Kanidm-native RADIUS / EAP-TLS backend**.

This document describes:

- supported security expectations,
- secure deployment guidance,
- vulnerability reporting expectations,
- cryptographic posture,
- non-destructive testing (NDT) constraints,
- and operational security recommendations.

---

## Supported Security Posture

This project is designed to support a high-assurance deployment model with:

- TLS 1.3 for RadSec transport,
- mutual TLS for incoming RadSec peers,
- strict peer certificate policy checks,
- EAP-TLS-only enforcement,
- fail-closed packet handling,
- bounded internal control-plane and metrology queues,
- private-key permission validation,
- structured audit logging,
- non-root runtime posture,
- crypto-agile / PQ-ready architectural intent.

---

## Supported Threat Model

The service is intended to reduce risk in scenarios such as:

- exposure of RADIUS traffic to untrusted network segments,
- unauthenticated or weakly authenticated RadSec peers,
- protocol misuse with unsupported EAP methods,
- malformed packet parsing risks,
- volumetric connection abuse,
- weak observability around session and proxy behavior,
- high-value environments requiring deterministic failure handling.

This service is **not** a complete defense against all threats. It should be deployed as one component within a broader security architecture.

---

## Cryptography and PQ Readiness

### Current intended cryptographic posture
- TLS 1.3
- mutual TLS for outer RadSec peers
- strong classical elliptic-curve key exchange defaults
- strict certificate validation
- fail-closed protocol handling

### PQ-ready posture
`kanidm_radsec_edge` is intended to remain **crypto-agile** and **post-quantum ready**.

In this project, **PQ-ready** means:

- architecture supports migration toward NIST-standardized post-quantum cryptography,
- hybrid deployment planning is expected,
- operator documentation should track PQ transition timelines,
- and changes should avoid preventing future support for hybrid PQ key exchange or PQ signatures where relevant.

PQ readiness in this document does **not** mean that every build or deployment automatically enables all PQ algorithms by default.

---

## Secure Deployment Expectations

### Required
- run as a **non-root** user
- mount `/etc/radsec` **read-only**
- enforce **read-only root filesystem** where possible
- drop all Linux capabilities
- enable `no-new-privileges`
- place the service behind appropriate network policy / firewall rules
- protect certificates and keys with strict filesystem permissions
- protect build and deployment pipelines with provenance controls

### Strongly recommended
- image signing and verification
- SBOM generation and dependency scanning
- host OS hardening per CIS/STIG guidance
- centralized logging and retention
- certificate lifecycle governance
- container runtime seccomp/apparmor confinement
- upstream Kanidm segmentation and monitoring
- replay-safe incident logging and timeline reconstruction

---

## Secrets and Key Material

### Private keys
The service validates private-key file permissions at startup and expects restrictive modes such as:

```text
0400 or 0600
```

### Configuration
Configuration files may contain security-sensitive routing and trust information. Treat them as controlled configuration artifacts.

### Shared secret
This transparent-proxy design assumes the same RADIUS shared secret is configured on the edge and the upstream Kanidm RADIUS backend unless packet re-signing is explicitly implemented.

---

## Non-Destructive Testing (NDT) Security

NDT is implemented internally using **shadow validation**.

### Security goals for NDT
- no externally reachable test control interface
- no mutation of live traffic for test-only paths
- bounded shadow queue
- safe fail behavior under queue pressure
- no raw packet export by default
- no privilege escalation path through test logic

### Forbidden patterns
- public replay APIs
- unauthenticated fault injection
- external packet mutation hooks in production
- unbounded internal test queues
- NDT paths that bypass edge policy

---

## Metrology Security

Metrology is intentionally bounded and internal.

### Expectations
- low-cardinality metrics only
- no external metrics endpoint in this revision
- no secrets in metrics
- cautious handling of certificate metadata
- queue pressure must not destabilize the data plane

### Logging guidance
- keep logs structured
- redact or minimize unnecessary PII
- forward logs to a central collector
- protect log integrity and retention
- correlate state transitions, reject reasons, and upstream timing

---

## Vulnerability Reporting

### Reporting
If you discover a security issue, do **not** disclose it publicly before maintainers have had a reasonable opportunity to assess and address it.

Use a private, controlled reporting channel appropriate to your environment, such as:

- internal security ticketing,
- private maintainer contact,
- or an established responsible disclosure workflow.

### Recommended report contents
Include:

- affected version / commit,
- exact deployment assumptions,
- reproduction steps,
- packet examples only if necessary and sanitized,
- exploitability and impact assessment,
- suggested mitigations if available.

### Disclosure expectations
Coordinated disclosure is preferred.
Public issue trackers should not be used for active exploitable details until triage and remediation planning are complete.

---

## Security Maintenance Expectations

Operators should maintain:

- routine dependency review,
- SBOM review,
- regression testing with malformed packet corpora,
- certificate policy review,
- upstream Kanidm connectivity and timeout monitoring,
- periodic validation of container and host hardening,
- periodic review of PQ migration readiness.

---

## Hardening Checklist

### Application
- [ ] EAP-TLS-only mode enabled
- [ ] `Message-Authenticator` enforcement enabled
- [ ] strict peer certificate policy configured
- [ ] fail-closed behavior verified
- [ ] shadow mode reviewed for bounded behavior
- [ ] metrology queues sized and monitored

### Runtime
- [ ] non-root execution
- [ ] read-only root filesystem
- [ ] `/etc/radsec` read-only
- [ ] all capabilities dropped
- [ ] no-new-privileges
- [ ] container/base image pinned and scanned

### PKI
- [ ] trusted client CA set reviewed
- [ ] peer certificate naming policy reviewed
- [ ] key permissions verified
- [ ] certificate renewal process documented
- [ ] revocation strategy defined at the organizational level

### Upstream
- [ ] Kanidm backend segmented
- [ ] Kanidm backend monitored
- [ ] shared secret alignment verified
- [ ] timeout and retry posture reviewed
- [ ] identity and authorization ownership clearly assigned to Kanidm

### Audit / Response
- [ ] centralized log forwarding configured
- [ ] retention requirements documented
- [ ] incident response procedure documented
- [ ] malformed traffic regression tests part of change pipeline
- [ ] state transition anomalies reviewed periodically

---

## Security Limitations

This revision does **not** currently provide:

- CRL / OCSP revocation enforcement,
- built-in packet re-signing,
- externalized secure admin API,
- externalized metrics service,
- turnkey compliance attestation,
- automatic PQ feature enablement in all build profiles.

---

## Recommended Next Security Enhancements

- CRL / OCSP support
- explicit hybrid PQ TLS deployment profiles
- upstream pool health checking
- stronger audit event taxonomy
- optional signed configuration bundles
- external metrics export with strong access controls
- documented secure operational runbooks
