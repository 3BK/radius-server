use crate::radius::{RadiusAttribute, ATTR_EAP_MESSAGE};

pub const EAP_CODE_REQUEST: u8 = 1;
pub const EAP_CODE_RESPONSE: u8 = 2;
pub const EAP_CODE_SUCCESS: u8 = 3;
pub const EAP_CODE_FAILURE: u8 = 4;

pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_TLS: u8 = 13;

#[derive(Debug, Clone)]
pub struct EapMeta {
    pub code: u8,
    pub identifier: u8,
    pub eap_type: Option<u8>,
}

pub fn concat_eap_message(attrs: &[RadiusAttribute]) -> Vec<u8> {
    attrs.iter()
        .filter(|a| a.typ == ATTR_EAP_MESSAGE)
        .flat_map(|a| a.value.clone())
        .collect()
}

pub fn parse_eap_message(attrs: &[RadiusAttribute]) -> Result<EapMeta, String> {
    let eap = concat_eap_message(attrs);

    if eap.len() < 4 {
        return Err("EAP-Message is missing or too short".to_string());
    }

    let code = eap[0];
    let identifier = eap[1];
    let length = u16::from_be_bytes([eap[2], eap[3]]) as usize;

    if length != eap.len() {
        return Err(format!(
            "EAP length mismatch: header says {}, actual {}",
            length,
            eap.len()
        ));
    }

    let eap_type = match code {
        EAP_CODE_REQUEST | EAP_CODE_RESPONSE => {
            if eap.len() < 5 {
                return Err("Typed EAP packet too short".to_string());
            }
            Some(eap[4])
        }
        _ => None,
    };

    Ok(EapMeta {
        code,
        identifier,
        eap_type,
    })
}

pub fn enforce_eap_tls_only(attrs: &[RadiusAttribute]) -> Result<EapMeta, String> {
    let meta = parse_eap_message(attrs)?;

    if meta.code != EAP_CODE_RESPONSE {
        return Err(format!(
            "Only EAP-Response is accepted in Access-Request, got code {}",
            meta.code
        ));
    }

    match meta.eap_type {
        Some(EAP_TYPE_IDENTITY) => Ok(meta),
        Some(EAP_TYPE_TLS) => Ok(meta),
        Some(EAP_TYPE_NAK) => Err("EAP NAK is not permitted in EAP-TLS-only mode".to_string()),
        Some(other) => Err(format!(
            "Unsupported EAP method {} in EAP-TLS-only mode",
            other
        )),
        None => Err("Missing EAP type in request".to_string()),
    }
}

pub fn build_eap_failure(identifier: u8) -> Vec<u8> {
    vec![EAP_CODE_FAILURE, identifier, 0x00, 0x04]
}
