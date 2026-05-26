use crate::control::{ControlEvent, ControlTx};
use crate::metrics::{MetricSample, MetricsTx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    AcceptedTcp,
    TlsHandshakeStarted,
    TlsEstablished,
    PeerIdentityValidated,
    RadiusFrameReceived,
    RadiusValidated,
    EapIdentityObserved,
    EapTlsObserved,
    UpstreamPending,
    UpstreamChallengeRelayed,
    UpstreamAcceptRelayed,
    UpstreamRejectRelayed,
    Closed,
    Error,
}

pub fn can_transition(from: SessionState, to: SessionState) -> bool {
    use SessionState::*;
    matches!(
        (from, to),
        (AcceptedTcp, TlsHandshakeStarted)
            | (TlsHandshakeStarted, TlsEstablished)
            | (TlsEstablished, PeerIdentityValidated)
            | (PeerIdentityValidated, RadiusFrameReceived)
            | (RadiusFrameReceived, RadiusValidated)
            | (RadiusValidated, EapIdentityObserved)
            | (RadiusValidated, EapTlsObserved)
            | (EapIdentityObserved, UpstreamPending)
            | (EapTlsObserved, UpstreamPending)
            | (UpstreamPending, UpstreamChallengeRelayed)
            | (UpstreamPending, UpstreamAcceptRelayed)
            | (UpstreamPending, UpstreamRejectRelayed)
            | (_, Closed)
            | (_, Error)
    )
}

#[derive(Debug, Clone)]
pub struct SessionTracker {
    session_id: u64,
    state: SessionState,
    control_tx: Option<ControlTx>,
    metrics_tx: Option<MetricsTx>,
}

impl SessionTracker {
    pub fn new(
        session_id: u64,
        control_tx: Option<ControlTx>,
        metrics_tx: Option<MetricsTx>,
    ) -> Self {
        Self {
            session_id,
            state: SessionState::AcceptedTcp,
            control_tx,
            metrics_tx,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn transition(&mut self, to: SessionState, reason: &'static str) -> Result<(), String> {
        if !can_transition(self.state, to) {
            if let Some(tx) = &self.metrics_tx {
                let _ = tx.try_send(MetricSample::StateViolation);
            }
            return Err(format!(
                "Illegal transition for session {}: {:?} -> {:?} ({})",
                self.session_id, self.state, to, reason
            ));
        }

        let from = self.state;
        self.state = to;

        if let Some(tx) = &self.control_tx {
            let _ = tx.try_send(ControlEvent::StateTransition {
                session_id: self.session_id,
                from,
                to,
                reason,
            });
        }

        Ok(())
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        if let Some(tx) = &self.control_tx {
            let _ = tx.try_send(ControlEvent::SessionClosed {
                session_id: self.session_id,
            });
        }
    }
}
