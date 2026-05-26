# docs/ARCHITECTURE.md

## Overview

`kanidm_radsec_edge` is a **Kanidm-aware RADIUS-over-TLS edge service** for **EAP-TLS-only** environments.

It is intended to provide:

- secure outer RadSec transport,
- strict protocol boundary enforcement,
- transparent upstream proxying to Kanidm,
- safe internal non-destructive testing (NDT),
- and bounded edge metrology.

The architecture is deliberately split so that:

- the **edge** owns transport, protocol enforcement, and observability,
- while **Kanidm** owns identity, RADIUS backend behavior, and EAP-TLS authority.

---

## High-Level Data Flow

```text
[NAD / AP / Controller / RadSec peer]
              |
          TCP + TLS
              |
      [kanidm_radsec_edge]
        - TLS 1.3 / mTLS
        - peer cert policy
        - RADIUS framing
        - EAP-TLS-only enforcement
        - control plane
        - shadow NDT
        - metrology
              |
          UDP RADIUS
              |
       [Kanidm RADIUS]
        - native RADIUS
        - native EAP-TLS
        - identity authority
```

---

## Plane Separation

The application is designed around three internal planes.

### 1. Data plane
Responsible for:

- TCP accept,
- TLS handshake,
- RADIUS packet framing,
- packet validation,
- EAP-TLS-only enforcement,
- upstream RADIUS exchange,
- response relay.

### 2. Control plane
Responsible for:

- session lifecycle events,
- state transition observation,
- shadow validation events,
- reject reason events,
- safe non-destructive testing hooks.

The control plane is internal-only and bounded.

### 3. Metrology plane
Responsible for:

- low-cardinality metric samples,
- queue-drop counters,
- latency summaries,
- session and reject counts,
- periodic metric flush events.

The metrology plane is internal-only and bounded.

---

## Main Components

### `main.rs`
Bootstraps the service:

- initializes structured logging,
- loads configuration,
- validates key permissions,
- builds TLS configuration,
- starts the server.

### `config.rs`
Defines the configuration model and local security checks:

- listener settings,
- TLS paths,
- peer policy,
- upstream destination,
- EAP policy,
- control-plane settings,
- metrology settings,
- private-key permission verification.

### `crypto.rs`
Defines the outer RadSec trust boundary:

- TLS 1.3 configuration,
- mutual client certificate validation,
- peer certificate metadata extraction,
- SHA-256 fingerprint support,
- SAN policy enforcement.

### `radius.rs`
Provides the RADIUS protocol primitives:

- packet parse / serialize,
- attribute parsing,
- `Message-Authenticator` verification,
- response authenticator verification,
- local reject packet construction.

### `eap.rs`
Provides EAP-specific guards:

- parse EAP payloads,
- enforce EAP-TLS-only policy,
- build local EAP-Failure payloads.

### `kanidm.rs`
Implements the transparent upstream RADIUS exchange toward Kanidm:

- UDP socket bind/connect,
- timeout-controlled send/recv,
- bounded packet receive.

### `state.rs`
Implements the explicit per-session state machine.

This is critical for:

- deterministic session lifecycle visibility,
- detecting illegal transitions,
- making NDT measurable and safe.

### `control.rs`
Defines internal control-plane events and shadow-work items.

### `metrics.rs`
Defines internal metric samples and aggregated metrology flush behavior.

### `server.rs`
Coordinates the live data path:

- accept and rate-limit connections,
- perform TLS handshake,
- validate peer identity,
- read framed packets,
- mirror packets into shadow validation,
- enforce RADIUS + EAP policy,
- proxy upstream to Kanidm,
- relay upstream responses,
- emit control-plane and metrology events.

---

## Session State Machine

The service models session progression explicitly.

### States
- `AcceptedTcp`
- `TlsHandshakeStarted`
- `TlsEstablished`
- `PeerIdentityValidated`
- `RadiusFrameReceived`
- `RadiusValidated`
- `EapIdentityObserved`
- `EapTlsObserved`
- `UpstreamPending`
- `UpstreamChallengeRelayed`
- `UpstreamAcceptRelayed`
- `UpstreamRejectRelayed`
- `Closed`
- `Error`

### Rationale
The explicit state machine exists to support:

- deterministic operational reasoning,
- illegal-transition detection,
- auditability,
- safe NDT,
- structured metrology.

---

## Trust Boundaries

### Boundary 1: Outer RadSec TLS
Incoming RadSec peers must satisfy:

- TLS 1.3 handshake,
- mutual certificate validation,
- optional fingerprint pinning,
- optional SAN policy constraints.

### Boundary 2: RADIUS packet validity
Incoming packets must satisfy:

- correct framing,
- valid length,
- valid attribute structure,
- supported RADIUS code,
- valid `Message-Authenticator` when enabled.

### Boundary 3: EAP-TLS-only policy
Incoming `EAP-Message` content must satisfy:

- valid EAP structure,
- supported EAP type,
- no method downgrade behavior,
- EAP-TLS-only enforcement.

### Boundary 4: Upstream response validity
Responses from Kanidm must satisfy:

- parseability,
- valid response authenticator,
- supported RADIUS response code.

---

## Transparent Proxy Design

This service uses a transparent proxy model.

### Benefits
- minimal mutation of packets,
- simpler correctness model,
- cleaner separation between edge and identity backend,
- less risk than implementing a full authenticator at the edge.

### Constraint
This design assumes the **same shared secret** on the edge and upstream Kanidm side unless packet re-signing is implemented.

---

## NDT Architecture

### Goal
Allow protocol and parser validation to be exercised safely without creating a separate exposed test plane.

### Mechanism
- mirror live packets into a bounded shadow queue,
- run parse / authenticator / EAP policy checks again,
- record shadow verdicts internally,
- never alter the live forwarding path from shadow behavior.

### Why bounded queues matter
Bounded queues ensure that test/diagnostic behavior cannot grow into an unbounded memory or stability risk.

---

## Metrology Architecture

### Captured dimensions
- sessions opened / closed,
- packet counts and bytes,
- TLS handshake timing,
- upstream RTT,
- reject categories,
- queue drops,
- state violations.

### Why internal-only in this revision
An internal-only metrics model avoids exposing a new network-visible service and keeps the attack surface smaller.

---

## PQ-Ready Architecture

The project is intended to remain **crypto-agile** and **PQ-ready**.

### What that means architecturally
- TLS provider and key-exchange choices should remain replaceable,
- deployment guidance should accommodate hybrid classical + PQ transitions,
- long-term hardening should not assume classical-only cryptography,
- future profiles can adopt standardized PQ and hybrid mechanisms without redesigning the service role.

### What it does not mean
- universal automatic enablement of PQ algorithms in every build,
- a claim that every dependency and peer in the path is already PQ-complete,
- a claim that compliance frameworks are satisfied solely by adding PQ features.

---

## Failure Handling Philosophy

The service is designed to fail closed for:

- malformed packets,
- unsupported methods,
- invalid authenticators,
- peer-policy mismatch,
- timeout and upstream exchange failure,
- invalid upstream responses,
- illegal state transitions.

This is intentional and appropriate for high-value environments.

---

## Security Boundaries for Operators

Operators should treat the following as distinct security domains:

1. RadSec peer trust
2. Edge host/container runtime
3. Kanidm upstream RADIUS trust
4. PKI and certificate lifecycle
5. Logging and metrology infrastructure
6. CI/CD and build provenance
7. PQ migration planning

---

## Future Architecture Enhancements

Potential future evolution paths include:

- CRL / OCSP integration,
- upstream pool and health checks,
- packet re-signing for split-secret topologies,
- externalized metrics with access controls,
- signed configuration bundles,
- explicit hybrid PQ TLS profiles,
- richer per-peer routing classes,
- and stronger audit event taxonomies.
