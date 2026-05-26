use hmac::{Hmac, Mac};
use md5::Md5;
use radsec_server::control::{spawn_shadow_actor, ControlEvent, ShadowWork};
use radsec_server::eap::{enforce_eap_tls_only, parse_eap_message};
use radsec_server::radius::{
    RadiusAttribute, RadiusPacket, ATTR_EAP_MESSAGE, ATTR_MESSAGE_AUTHENTICATOR,
    CODE_ACCESS_REQUEST,
};
use tokio::sync::mpsc;

type HmacMd5 = Hmac<Md5>;

fn build_packet_with_attrs(attrs: Vec<RadiusAttribute>, secret: &[u8]) -> Vec<u8> {
    let mut pkt = RadiusPacket {
        code: CODE_ACCESS_REQUEST,
        identifier: 1,
        authenticator: [
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0x10, 0x20,
        ],
        attributes: attrs,
    };

    let zeroed = pkt.with_zeroed_message_authenticator();
    let bytes = zeroed.to_bytes().expect("serialize zeroed");

    let mut mac = HmacMd5::new_from_slice(secret).expect("valid hmac key");
    mac.update(&bytes);
    let digest = mac.finalize().into_bytes();

    for attr in &mut pkt.attributes {
        if attr.typ == ATTR_MESSAGE_AUTHENTICATOR {
            attr.value = digest.to_vec();
        }
    }

    pkt.to_bytes().expect("serialize final")
}

fn build_valid_tls_request(secret: &[u8]) -> Vec<u8> {
    let eap = vec![2u8, 0x01, 0x00, 0x06, 13u8, 0x80]; // EAP-Response / TLS / flags
    build_packet_with_attrs(
        vec![
            RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: eap,
            },
            RadiusAttribute {
                typ: ATTR_MESSAGE_AUTHENTICATOR,
                value: vec![0u8; 16],
            },
        ],
        secret,
    )
}

fn built_in_malformed_corpus() -> Vec<(&'static str, Vec<u8>)> {
    let secret = b"radsec";
    let mut cases = Vec::new();

    // 1) Too short to be RADIUS.
    cases.push(("radius_too_short", vec![0x01, 0x02, 0x00, 0x14, 0x00]));

    // 2) Header length mismatch (claims 20, actual 24).
    let mut mismatch = vec![0u8; 24];
    mismatch[0] = CODE_ACCESS_REQUEST;
    mismatch[1] = 0x01;
    mismatch[2] = 0x00;
    mismatch[3] = 0x14;
    cases.push(("radius_length_mismatch", mismatch));

    // 3) Invalid attribute length = 1.
    let mut bad_attr_len = vec![0u8; 22];
    bad_attr_len[0] = CODE_ACCESS_REQUEST;
    bad_attr_len[1] = 0x01;
    bad_attr_len[2] = 0x00;
    bad_attr_len[3] = 0x16;
    // 16-byte authenticator already zero
    bad_attr_len[20] = ATTR_EAP_MESSAGE;
    bad_attr_len[21] = 0x01;
    cases.push(("radius_attr_len_one", bad_attr_len));

    // 4) Attribute overruns packet boundary.
    let mut overrun = vec![0u8; 22];
    overrun[0] = CODE_ACCESS_REQUEST;
    overrun[1] = 0x01;
    overrun[2] = 0x00;
    overrun[3] = 0x16;
    overrun[20] = ATTR_EAP_MESSAGE;
    overrun[21] = 0x20;
    cases.push(("radius_attr_overrun", overrun));

    // 5) EAP length mismatch.
    let eap_bad_len = build_packet_with_attrs(
        vec![
            RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: vec![2u8, 0x99, 0x00, 0x09, 13u8, 0x80], // says 9, actual 6
            },
            RadiusAttribute {
                typ: ATTR_MESSAGE_AUTHENTICATOR,
                value: vec![0u8; 16],
            },
        ],
        secret,
    );
    cases.push(("eap_length_mismatch", eap_bad_len));

    // 6) Missing EAP type (header only).
    let eap_missing_type = build_packet_with_attrs(
        vec![
            RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: vec![2u8, 0x22, 0x00, 0x04], // No type byte
            },
            RadiusAttribute {
                typ: ATTR_MESSAGE_AUTHENTICATOR,
                value: vec![0u8; 16],
            },
        ],
        secret,
    );
    cases.push(("eap_missing_type", eap_missing_type));

    // 7) Unsupported EAP method.
    let eap_unsupported = build_packet_with_attrs(
        vec![
            RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: vec![2u8, 0x23, 0x00, 0x06, 25u8, 0x00], // PEAP-like / unsupported in EAP-TLS-only
            },
            RadiusAttribute {
                typ: ATTR_MESSAGE_AUTHENTICATOR,
                value: vec![0u8; 16],
            },
        ],
        secret,
    );
    cases.push(("eap_unsupported_method", eap_unsupported));

    // 8) Missing Message-Authenticator.
    let no_msg_auth = {
        let eap = vec![2u8, 0x24, 0x00, 0x06, 13u8, 0x80];
        let pkt = RadiusPacket {
            code: CODE_ACCESS_REQUEST,
            identifier: 9,
            authenticator: [0x11; 16],
            attributes: vec![RadiusAttribute {
                typ: ATTR_EAP_MESSAGE,
                value: eap,
            }],
        };
        pkt.to_bytes().expect("serialize")
    };
    cases.push(("missing_message_auth", no_msg_auth));

    // 9) Tampered valid request (authenticator mismatch).
    let mut tampered = build_valid_tls_request(secret);
    let last = tampered.last_mut().expect("non-empty");
    *last ^= 0xFF;
    cases.push(("tampered_message_auth", tampered));

    cases
}

#[test]
fn malformed_corpus_never_panics_radius_parser_or_eap_enforcer() {
    let corpus = built_in_malformed_corpus();

    for (name, sample) in corpus {
        let parse_result = std::panic::catch_unwind(|| RadiusPacket::parse(&sample, 4096));
        assert!(parse_result.is_ok(), "radius parser panicked on sample: {name}");

        if let Ok(Ok(pkt)) = parse_result {
            let eap_parse = std::panic::catch_unwind(|| parse_eap_message(&pkt.attributes));
            assert!(eap_parse.is_ok(), "eap parser panicked on sample: {name}");

            let eap_enforce = std::panic::catch_unwind(|| enforce_eap_tls_only(&pkt.attributes));
            assert!(
                eap_enforce.is_ok(),
                "eap enforcer panicked on sample: {name}"
            );
        }
    }
}

#[test]
fn malformed_corpus_expected_failures_are_rejected() {
    let corpus = built_in_malformed_corpus();

    for (name, sample) in corpus {
        match RadiusPacket::parse(&sample, 4096) {
            Err(_) => {
                // Packet-level malformed: good outcome.
            }
            Ok(pkt) => {
                // If packet parses, EAP-TLS-only should still reject malformed or unsupported EAP.
                let _ = parse_eap_message(&pkt.attributes); // may fail or succeed depending on case
                let enforced = enforce_eap_tls_only(&pkt.attributes);

                // We only expect success for a genuinely valid TLS request, which this malformed corpus excludes.
                assert!(
                    enforced.is_err(),
                    "sample {name} unexpectedly passed EAP-TLS-only enforcement"
                );
            }
        }
    }
}

#[test]
fn valid_reference_case_still_passes_as_regression_anchor() {
    let pkt = build_valid_tls_request(b"radsec");
    let parsed = RadiusPacket::parse(&pkt, 4096).expect("valid packet parse");

    parsed
        .verify_request_message_authenticator(b"radsec")
        .expect("valid Message-Authenticator");

    let eap = parse_eap_message(&parsed.attributes).expect("valid eap parse");
    assert_eq!(eap.eap_type, Some(13u8));

    enforce_eap_tls_only(&parsed.attributes).expect("valid eap-tls");
}

#[tokio::test]
async fn malformed_corpus_shadow_actor_reports_rejections_without_panicking() {
    let (control_tx, mut control_rx) = mpsc::channel(64);
    let (shadow_tx, shadow_rx) = mpsc::channel(64);

    spawn_shadow_actor(shadow_rx, Some(control_tx));

    for (idx, (_name, sample)) in built_in_malformed_corpus().into_iter().enumerate() {
        shadow_tx
            .send(ShadowWork {
                session_id: idx as u64 + 1,
                packet: sample,
                max_packet_size: 4096,
                require_message_authenticator: true,
                shared_secret: "radsec".to_string(),
                enforce_eap_tls_only: true,
            })
            .await
            .expect("shadow send");
    }

    // Every malformed sample should yield exactly one shadow verdict.
    let mut seen = 0usize;
    while seen < built_in_malformed_corpus().len() {
        let event = control_rx.recv().await.expect("shadow verdict");
        match event {
            ControlEvent::ShadowVerdict {
                accepted, reason, ..
            } => {
                assert!(
                    !accepted,
                    "malformed corpus sample unexpectedly accepted in shadow mode"
                );
                assert!(
                    reason.contains("shadow_"),
                    "unexpected shadow verdict reason: {reason}"
                );
                seen += 1;
            }
            other => panic!("unexpected control event while draining corpus: {other:?}"),
        }
    }
}
