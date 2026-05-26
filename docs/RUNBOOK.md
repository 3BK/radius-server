# docs/RUNBOOK.md

## Purpose

This runbook provides **day-2 operational guidance** for **`kanidm_radsec_edge`** in production.

It is intended for operators, on-call responders, platform engineers, and security personnel responsible for:

- startup and change verification,
- routine operational review,
- troubleshooting,
- incident triage,
- safe rollback,
- and controlled recovery actions.

The service is assumed to be deployed as a **Kanidm-aware, EAP-TLS-only RadSec edge**.

---

## Service Summary

### Service role
`kanidm_radsec_edge` is the **RadSec transport and enforcement edge**.

### It is responsible for
- outer TLS 1.3 / mTLS for RadSec peers
- peer certificate policy checks
- RADIUS packet validation
- EAP-TLS-only enforcement
- transparent upstream proxying to Kanidm
- internal NDT shadow validation
- internal edge metrology

### It is not responsible for
- identity source-of-truth
- backend EAP-TLS authority
- NAC policy ownership
- certificate issuance workflows
- external test control planes

---

## Key Paths and Settings

### Default config path
```text
/etc/radsec/config.toml
```

### Config override
```text
RADSEC_CONFIG
```

### Expected files
```text
/etc/radsec/config.toml
/etc/radsec/server.pem
/etc/radsec/server.key
/etc/radsec/client_ca.pem
```

### Default listener
```text
TCP 2083
```

### Upstream
Configured in:
```toml
[upstream]
address = "host:port"
```

---

## Normal Operational Expectations

Under normal operation, you should expect to see:

- successful startup log event
- listener bind log on configured address
- successful TLS handshakes from approved RadSec peers
- RADIUS packet receive / validation flow
- EAP-TLS-only accepted behavior
- upstream Kanidm exchange RTTs within expected baseline
- periodic metrology flush events
- reject events only for policy- or traffic-expected cases

---

## Startup Procedure

### 1. Validate deployment inputs
Before starting the service, verify:

- config file present
- server certificate present
- client CA present
- private key present
- private key permissions are `0400` or `0600`
- upstream Kanidm address is correct
- firewall/network policy in place
- expected image/binary version selected

### 2. Start service
Start using your service manager, container runtime, or orchestration platform.

### 3. Confirm startup events
Look for:

- startup initialization log
- network bind success
- no private-key permission error
- no config parse error
- no TLS initialization error

### 4. Validate listener
Confirm that the service is listening on the configured TCP socket.

### 5. Validate a known-good peer flow
Use a controlled, approved peer or canary path to confirm:

- TLS handshake success
- peer-policy success
- Access-Request observed
- expected challenge/accept flow from Kanidm

---

## Routine Daily / Shift Checks

### Health review
Review:

- service uptime
- restart count
- listener availability
- CPU and memory baseline
- queue-drop metrics
- state-violation counts
- reject trends
- upstream RTT trends

### Log review
Check for:

- repeated TLS handshake failures
- repeated peer-policy rejects
- malformed packet rejects
- repeated upstream timeouts
- unexpected Access-Reject spikes
- queue-drop spikes
- state violation events

### Dependency review
Confirm:

- Kanidm backend reachable
- certificate expiry horizon acceptable
- config drift not observed
- no unauthorized peer additions detected

---

## Standard Operating Tasks

## Task: Verify current runtime config selection

### Objective
Confirm which config file the service is using.

### Steps
1. Check service environment/config injection.
2. Confirm `RADSEC_CONFIG` if overridden.
3. If unset, assume default `/etc/radsec/config.toml`.
4. Compare deployed file to approved source.

### Expected outcome
The running service uses the approved config artifact.

---

## Task: Verify key permissions

### Objective
Ensure private-key permissions remain compliant.

### Steps
1. Inspect `/etc/radsec/server.key`
2. Confirm owner/group as expected
3. Confirm mode is `0400` or `0600`
4. Confirm mount path is read-only if containerized

### Expected outcome
Private key is not group-readable or world-readable.

---

## Task: Validate peer certificate policy

### Objective
Confirm only approved RadSec peers are allowed.

### Steps
1. Review `[peer_policy]` settings
2. Check fingerprints / SAN rules
3. Compare recent handshake logs against approved peer inventory
4. Investigate any new or unknown fingerprints immediately

### Expected outcome
Only known and policy-compliant peers establish sessions.

---

## Task: Validate upstream connectivity

### Objective
Ensure the edge can reach Kanidm.

### Steps
1. Confirm configured `[upstream]` address
2. Verify route/firewall path
3. Review upstream timeout/reject logs
4. Use controlled synthetic health validation outside production peak if necessary

### Expected outcome
Kanidm upstream exchanges succeed within expected latency.

---

## Incident Categories

The following sections describe common incident classes and responses.

---

## Incident: Service fails to start

### Possible symptoms
- process exits immediately
- container crash loop
- no listener bound
- startup permission/config error in logs

### Common causes
- invalid TOML config
- missing config file
- missing certificate/key file
- insecure private-key permissions
- TLS material invalid or unreadable
- port already in use

### Immediate actions
1. Check startup logs
2. Confirm file presence and permissions
3. Validate config syntax against approved source
4. Check listener port conflict
5. Roll back to last known good config if recent change introduced issue

### Escalation
Escalate to:
- platform engineering if host/runtime issue
- security/PKI owner if certificate problem
- change owner if recent config change caused failure

---

## Incident: TLS handshake failures spike

### Possible symptoms
- repeated handshake failure logs
- valid peers unable to connect
- service up but no successful sessions

### Common causes
- incorrect trusted client CA
- peer certificate expired
- peer cert no longer matches policy
- PKI rotation mismatch
- TLS interoperability issue
- network middlebox interference

### Immediate actions
1. Identify affected peer(s)
2. Review peer fingerprint / SAN details in logs
3. Verify current CA trust bundle
4. Check whether peer cert rotated unexpectedly
5. Confirm no recent peer-policy change was deployed
6. If broad impact, compare with previous working image/config

### Containment guidance
Do **not** disable peer policy broadly in production without change authority.
Prefer:
- rollback of recent change
- controlled addition of known-good peer material
- staged PKI correction

---

## Incident: Unsupported EAP methods observed

### Possible symptoms
- reject spikes with EAP policy reasons
- Access-Requests arriving but immediately rejected
- new infrastructure reports authentication failure

### Common causes
- peer sending PEAP/TTLS/MSCHAP/other unsupported methods
- endpoint or controller misconfiguration
- unintended fallback behavior on clients
- newly introduced network device policy difference

### Immediate actions
1. Confirm reject reason in logs
2. Identify source peer / controller
3. Verify controller and supplicant profile is configured for **EAP-TLS**
4. Do not relax EAP-TLS-only policy without explicit approval

### Resolution
Correct the peer/supplicant configuration to use EAP-TLS.

---

## Incident: Upstream Kanidm timeouts increase

### Possible symptoms
- upstream timeout errors
- increased local reject behavior
- elevated RTT in metrology
- authentication latency complaints

### Common causes
- Kanidm backend overload
- network path degradation
- firewall changes
- DNS/routing issue if upstream indirection is used
- degraded host/container resources

### Immediate actions
1. Confirm whether timeouts are localized or widespread
2. Review upstream RTT trends
3. Verify Kanidm backend health
4. Confirm no recent network policy change
5. Check service resource saturation
6. If change-correlated, consider controlled rollback

### Escalation
Escalate to Kanidm/backend owners and network team as appropriate.

---

## Incident: Queue-drop metrics increase

### Possible symptoms
- `queue_drop_*` metrics increase
- reduced shadow/metrology fidelity
- possible pressure on internal bounded queues

### Meanings
- `queue_drop_control` => control-plane event pressure
- `queue_drop_shadow` => NDT shadow-path pressure
- `queue_drop_metrics` => metrology queue pressure

### Immediate actions
1. Determine which queue is dropping
2. Review traffic burst patterns
3. Review CPU/memory pressure
4. Increase queue capacity only through controlled change
5. Confirm data plane remains stable

### Key point
Queue drops are a **signal**, but bounded queues are a deliberate safety feature.  
Do not convert queues to unbounded as a quick fix.

---

## Incident: State-violation metrics increase

### Possible symptoms
- `state_violations` increase
- unusual protocol sequencing
- unexpected parser or flow behavior

### Potential causes
- malformed traffic
- implementation bug
- regression introduced in a new release
- shadow/data path divergence
- unexpected peer behavior

### Immediate actions
1. Review correlated log events
2. Identify session IDs / peer sources if available
3. Review malformed corpus regression pass/fail status
4. Compare current artifact to last known good release
5. If suspicious, increase monitoring and consider traffic sampling at the network boundary

### Escalation
Escalate to maintainers/engineering for potential parser/state-machine defect analysis.

---

## Incident: Unexpected Access-Reject spike

### Possible symptoms
- valid users/devices stop authenticating
- reject counts increase sharply
- no obvious service crash

### Common causes
- upstream Kanidm issue
- peer-policy mismatch
- unsupported EAP sent by peer
- shared secret misalignment
- timeout-induced local reject path

### Immediate actions
1. Determine reject category from logs/metrics
2. Separate policy rejects from upstream/timeout rejects
3. Validate shared secret alignment
4. Validate upstream reachability
5. Check whether peer or PKI changes occurred
6. Roll back recent edge config change if indicated

---

## Controlled Change Procedure

### Before change
- confirm approved change record
- export current config
- record current image/binary digest
- record certificate versions / fingerprints
- review rollback plan
- confirm maintenance window or canary path

### Change execution
- deploy to canary or staging first when possible
- validate startup
- validate known-good peer flow
- observe queue and metrology baselines
- compare reject rates before/after change

### After change
- confirm no unexpected handshake failures
- confirm no EAP policy regressions
- confirm no upstream RTT anomaly
- document deployment completion
- archive changed artifacts and evidence

---

## Rollback Procedure

### Trigger conditions
Rollback should be considered if:
- startup fails
- handshake failures spike broadly
- unsupported reject rates spike unexpectedly
- upstream RTT or timeout rates degrade materially
- state violations appear after release
- a change window introduces regression

### Rollback steps
1. Stop or remove the newly introduced deployment
2. Restore last known good image/binary
3. Restore last known good config
4. Restore previous certificate set if cert change was part of the event
5. Revalidate listener, peer flow, and upstream behavior
6. Preserve logs and deployment metadata for post-incident review

---

## NDT Operational Guidance

### Allowed use in production
- internal shadow validation only
- passive comparison / observation
- bounded queue behavior

### Not allowed in production
- externally triggered replay endpoints
- public fault injection
- ad hoc packet mutation hooks
- bypassing peer or EAP policy for testing convenience

### Safe validation pattern
Use:
- canary deployments
- staging environments
- regression corpus tests
- controlled peer simulations during approved windows

---

## PQ-Ready Operational Guidance

### Objective
Maintain the edge as **crypto-agile** and ready for controlled migration toward hybrid or standardized PQ-capable TLS postures.

### Operational expectations
- track TLS provider and dependency updates
- maintain compatibility test plans for hybrid PQ transport
- document peer classes that are classical-only
- maintain an approved PQ migration roadmap
- validate PQ-related changes in pre-production before rollout

### What not to do
- do not label every build “PQ enabled” without testing
- do not enable new PQ key-exchange preferences in production blindly
- do not skip interoperability validation with real peers and backends

---

## Evidence and Record Keeping

Maintain records for:

- deployment version and image digest
- config version
- certificate inventory
- peer-policy inventory
- validation results
- rollback evidence
- malformed corpus regression results
- metrology baselines
- incident timeline if applicable
- PQ migration decision records

---

## Escalation Matrix (Template)

### Platform / runtime
Use for:
- container runtime issues
- host resource issues
- filesystem mount issues
- listener failures unrelated to app logic

### PKI / security engineering
Use for:
- certificate validity issues
- CA trust problems
- fingerprint/SAN policy mismatches
- PKI rotation failures

### Identity / Kanidm owners
Use for:
- upstream RADIUS failures
- backend authentication/reject anomalies
- EAP-TLS backend behavior
- authorization/identity source issues

### Application maintainers
Use for:
- parser defects
- state-machine anomalies
- queue-behavior regressions
- release regressions
- malformed corpus failures

---

## Operator Checklist

### Daily / per shift
- [ ] service healthy
- [ ] no unusual restart count
- [ ] handshake failures within baseline
- [ ] upstream RTT within baseline
- [ ] reject rates within baseline
- [ ] queue drops reviewed
- [ ] state violations reviewed
- [ ] certificate expiry horizon reviewed where scheduled

### Weekly
- [ ] compare config drift against approved source
- [ ] verify image/binary provenance
- [ ] review recent malformed corpus test runs
- [ ] review peer inventory changes
- [ ] review monitoring alert quality

### Per change
- [ ] canary/staging validation completed
- [ ] rollback artifact ready
- [ ] startup verified
- [ ] known-good flow tested
- [ ] upstream validated
- [ ] metrics baseline compared
- [ ] evidence archived

---

## Summary

This runbook exists to keep `kanidm_radsec_edge` operating safely as:

- a **RadSec enforcement edge**,
- an **EAP-TLS-only boundary**,
- a **transparent Kanidm-aware proxy**,
- and a **securely testable, measurable** production component.

The service should be operated conservatively:

- fail closed,
- keep secrets and PKI tightly controlled,
- treat queue signals as operational telemetry,
- and preserve a deliberate, staged, PQ-ready migration posture.
