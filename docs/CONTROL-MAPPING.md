# docs/CONTROL-MAPPING.md

## Purpose

This document provides a **readiness-oriented control mapping** for `kanidm_radsec_edge`.

It is intended to show how the service’s current architecture and implementation patterns can help support selected control objectives from:

- **NIST SP 800-53 Rev. 5**
- **PCI DSS 4.0**
- **NIST STIG**
- **CIS**
- **ISO 27001**

> **Important**
>
> This is a **supporting control mapping**, not a formal attestation, assessment, or certification statement.
>
> Many control requirements depend on deployment, process, operating system configuration, monitoring, retention, administrative procedures, and organizational governance outside the application.

---

## Mapping Method

Each entry contains:

- **Control family / domain**
- **Readiness contribution from `kanidm_radsec_edge`**
- **Deployment/operational dependencies**
- **Residual notes**

---

# NIST SP 800-53 Rev. 5 Readiness Mapping

## AU - Audit and Accountability

### AU-2 / AU-3 / AU-12
**Readiness contribution**
- structured JSON logging
- explicit reject reasons
- internal control-plane events
- explicit state transitions
- metrology flush events

**Dependencies**
- centralized log aggregation
- log retention
- time synchronization
- alerting and review processes

**Residual notes**
- event retention and alert routing are external to the application

---

## SC - System and Communications Protection

### SC-8 / SC-12 / SC-13
**Readiness contribution**
- TLS 1.3 transport
- mutual certificate authentication
- peer certificate policy checks
- strong transport boundary at the RadSec edge

**Dependencies**
- PKI hygiene
- certificate lifecycle management
- trust-anchor governance
- secure upstream topology

**Residual notes**
- revocation handling is not yet implemented in this revision

### SC-5
**Readiness contribution**
- bounded per-IP rate limiting
- bounded internal queues
- packet validation
- timeout controls

**Dependencies**
- host/network DoS controls
- upstream protection
- runtime resource governance

**Residual notes**
- volumetric resilience is improved but not absolute

### SC-30 / crypto agility considerations
**Readiness contribution**
- PQ-ready / crypto-agile architectural intent
- migration-friendly design
- no dependence on password-based EAP methods at the edge

**Dependencies**
- provider support
- peer interoperability
- organizational PQ migration planning

**Residual notes**
- PQ readiness is a migration posture, not a universal default enablement claim

---

## IA - Identification and Authentication

### IA-3 / IA-5
**Readiness contribution**
- mutual TLS for RadSec peers
- EAP-TLS-only enforcement at the edge
- identity authority delegated to Kanidm backend

**Dependencies**
- certificate issuance and lifecycle
- Kanidm policy correctness
- endpoint certificate governance

**Residual notes**
- this edge does not replace backend identity authority

---

## SI - System and Information Integrity

### SI-10
**Readiness contribution**
- strict packet parse/validate
- malformed input reject path
- shadow regression corpus support
- fuzz-regression starter files

**Dependencies**
- test pipeline execution
- dependency hygiene
- malformed corpus maintenance

**Residual notes**
- parser correctness still depends on ongoing test coverage

### SI-4
**Readiness contribution**
- internal metrology
- queue-drop counters
- reject counters
- state-violation counting

**Dependencies**
- external monitoring stack
- alert thresholds
- operational review

**Residual notes**
- monitoring integration remains an operator responsibility

---

## CM - Configuration Management

### CM-2 / CM-6
**Readiness contribution**
- explicit TOML config model
- deterministic startup validation
- fail-closed on key permission issues
- support for immutable container deployment

**Dependencies**
- configuration change control
- artifact provenance
- environment-specific hardening

**Residual notes**
- configuration authorization and approval are external processes

---

# PCI DSS 4.0 Readiness Mapping

## Requirement 2 - Secure configurations

**Readiness contribution**
- non-root runtime posture
- minimal runtime image guidance
- read-only filesystem guidance
- tightly scoped config and key paths
- private-key permission enforcement

**Dependencies**
- hardened host/container baseline
- secure image build
- deployment enforcement

**Residual notes**
- PCI assessment depends on full environment, not application alone

---

## Requirement 4 - Protect cardholder data with strong cryptography during transmission

**Readiness contribution**
- TLS 1.3 transport
- mutual certificate authentication
- RADIUS-over-TLS boundary protection
- EAP-TLS-only policy enforcement

**Dependencies**
- certificate governance
- upstream secure deployment
- cardholder data flow scoping

**Residual notes**
- data classification and PCI scoping are external activities

---

## Requirement 6 - Secure systems and software

**Readiness contribution**
- bounded parser behavior
- malformed corpus regression tests
- structured build model
- fail-closed protocol enforcement
- PQ-ready migration posture for long-term crypto planning

**Dependencies**
- secure SDLC
- dependency scanning
- SBOM and vulnerability management
- code review and release control

**Residual notes**
- software security governance extends beyond code features

---

## Requirement 10 - Log and monitor access

**Readiness contribution**
- structured JSON logging
- explicit session events
- reject reason visibility
- metrology snapshots

**Dependencies**
- centralized logging
- tamper resistance
- retention
- review procedures

**Residual notes**
- this project emits logs; operators must secure and review them

---

# NIST STIG / CIS Readiness Mapping

## Least functionality / minimal attack surface

**Readiness contribution**
- minimal service purpose
- no external test API
- no external metrics endpoint in this revision
- intended minimal runtime image
- non-root execution guidance

**Dependencies**
- host/container hardening
- disabled unnecessary packages/services
- runtime profile enforcement

---

## File permissions / secret handling

**Readiness contribution**
- startup key-permission validation
- local secret and certificate path discipline
- read-only mount guidance

**Dependencies**
- underlying filesystem ownership
- orchestrator volume controls
- secrets handling procedures

---

## Network exposure reduction

**Readiness contribution**
- single primary listener role
- internal-only control plane
- internal-only metrology plane
- intended firewall/network policy restriction

**Dependencies**
- network segmentation
- host firewall policy
- container network policy

---

## Logging and monitoring

**Readiness contribution**
- JSON logs
- session and transport events
- protocol-reject visibility
- state-violation signals

**Dependencies**
- SIEM / log shipping
- detection rules
- review workflow

---

# ISO 27001 Readiness Mapping

## Annex A themes supported by this service

### Access control / identity support
**Readiness contribution**
- strong mutual TLS for peers
- EAP-TLS-only policy at the edge
- identity authority delegated to Kanidm

### Cryptographic controls
**Readiness contribution**
- TLS 1.3 transport protection
- certificate-based peer authentication
- PQ-ready migration posture

### Operations security
**Readiness contribution**
- bounded queues
- fail-closed handling
- timeout controls
- metrology snapshots
- regression-oriented testing support

### Logging and monitoring
**Readiness contribution**
- structured logs
- meaningful security events
- deterministic session lifecycle visibility

### Secure development and change
**Readiness contribution**
- explicit code modularization
- parser and malformed corpus tests
- shadow validation concept
- production-safe internal NDT model

**Dependencies across ISO**
- ISMS governance
- risk treatment
- asset ownership
- evidence retention
- supplier/dependency management
- incident management procedures

---

# PQ Readiness Mapping

## Why PQ readiness appears in control mapping

PQ readiness is relevant because long-lived confidentiality and integrity obligations in regulated environments may outlive classical cryptographic assumptions.

## Readiness contribution from `kanidm_radsec_edge`
- crypto-agile architecture
- migration-friendly transport role
- documentation that avoids overclaiming current default PQ enablement
- edge role that can adopt hybrid PQ transport profiles without taking on identity-provider responsibilities

## Dependencies
- provider maturity
- operational interoperability testing
- PKI / certificate ecosystem planning
- organizational PQ roadmap

## Residual notes
- PQ readiness is a programmatic and architectural objective, not a single switch

---

# Residual Risk Notes

The following remain outside the direct scope of the current application revision:

- formal compliance certification
- PKI lifecycle processes
- revocation checking
- host hardening
- image signing and provenance
- centralized log retention
- SIEM rule design
- incident response execution
- upstream identity correctness
- enterprise PQ transformation planning

---

# Recommended Evidence for Auditors / Reviewers

Operators may wish to maintain evidence such as:

- architecture diagrams
- container hardening configuration
- key permission evidence
- build and SBOM records
- dependency scan reports
- regression / malformed corpus test evidence
- change records
- logging retention configuration
- upstream Kanidm trust and configuration records
- PQ migration roadmap or design notes

---

# Summary

`kanidm_radsec_edge` can help support readiness-oriented control objectives by providing:

- secure RadSec transport,
- strict EAP-TLS-only enforcement,
- deterministic fail-closed behavior,
- internal safe NDT,
- bounded metrology,
- and a crypto-agile / PQ-ready architecture.

It should be treated as a **security control component** within a broader compliant system, not as a standalone source of compliance.
``
