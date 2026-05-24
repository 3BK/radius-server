use crate::config::ServerConfig;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// Note: These imports depend on the specific internals of the `radius-server` crate.
// Adjust the exact path to `RadiusMsg` and `Dictionary` based on the crate version.
use radius_server::dictionary::Dictionary;
use radius_server::radius_packet::{RadiusMsg, TypeCode};

/// The RFC 6614 mandated shared secret for all RadSec communications.
const RADSEC_SHARED_SECRET: &str = "radsec";

pub async fn run(cfg: ServerConfig, tls_config: rustls::ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&cfg.bind_address).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // NIST SC-5: Volumetric DoS Protection
    let quota = Quota::per_second(NonZeroU32::new(cfg.max_connections_per_sec).unwrap());
    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    info!(
        action = "network_bind",
        address = %cfg.bind_address,
        status = "success",
        "Listening for RadSec connections"
    );

    // Load the RADIUS Dictionary once to pass into our packet handlers
    let dictionary = Dictionary::from_file("./dictionary").unwrap_or_else(|_| Dictionary::from_string(""));
    let dictionary = Arc::new(dictionary);

    // Graceful Shutdown Channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for ctrl_c");
        info!(action = "shutdown_signal", "Received termination signal, shutting down gracefully...");
        let _ = shutdown_tx.send(()).await;
    });

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let ip = peer_addr.ip();

                        if rate_limiter.check_key(&ip).is_err() {
                            warn!(
                                action = "rate_limit_exceeded",
                                source_ip = %ip,
                                status = "dropped",
                                "Connection dropped due to rate limiting"
                            );
                            continue;
                        }

                        let tls_acceptor = tls_acceptor.clone();
                        let dict_clone = Arc::clone(&dictionary);

                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    info!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        status = "success",
                                        "mTLS session established (P-384/PQ)"
                                    );

                                    match radsec_stream_handler(tls_stream, dict_clone).await {
                                        Ok(_) => info!(action = "radius_session", source_ip = %ip, status = "closed"),
                                        Err(e) => error!(action = "radius_session", source_ip = %ip, status = "error", error = %e),
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        action = "tls_handshake",
                                        source_ip = %ip,
                                        status = "failed",
                                        error = %e,
                                        "TLS handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(action = "network_accept", error = %e, "Failed to accept connection");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!(action = "server_shutdown", "Server stopped accepting new connections");
                break;
            }
        }
    }

    Ok(())
}

/// Implements RFC 6614 (RadSec) TCP Stream Framing
async fn radsec_stream_handler(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    dictionary: Arc<Dictionary>,
) -> Result<(), std::io::Error> {
    let mut header_buf = [0u8; 4];

    loop {
        // 1. Read the first 4 bytes (Code [1], Identifier [1], Length [2])
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!(action = "tls_session_end", "Client disconnected gracefully");
                break;
            }
            Err(e) => return Err(e),
        }

        // 2. Extract Length (Bytes 2 and 3 are Big-Endian)
        let length = u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize;

        // RFC 2865 enforces a minimum length of 20 bytes and maximum of 4096 bytes
        if !(20..=4096).contains(&length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("RFC 6614 Violation: Invalid RADIUS packet length: {}", length),
            ));
        }

        // 3. Read the remaining payload (Length - 4 bytes already read)
        let mut payload = vec![0u8; length - 4];
        stream.read_exact(&mut payload).await?;

        // 4. Reconstruct the full RADIUS packet
        let mut full_packet = header_buf.to_vec();
        full_packet.extend_from_slice(&payload);

        debug!(
            action = "packet_received",
            size = length,
            "Successfully framed RadSec packet"
        );

        // 5. Process the packet using the dictionary and shared secret
        let response_bytes = process_radius_packet(&full_packet, &dictionary).await?;

        // 6. Write the response back over the mTLS stream
        if !response_bytes.is_empty() {
            stream.write_all(&response_bytes).await?;
            stream.flush().await?;
        }
    }

    Ok(())
}

/// Parses the RFC 2865 payload and implements Zero-Trust Authentication logic.
async fn process_radius_packet(
    request_bytes: &[u8],
    dictionary: &Dictionary,
) -> Result<Vec<u8>, std::io::Error> {
    
    // 1. Parse raw bytes into a RadiusMsg
    let mut request = match RadiusMsg::from_bytes(request_bytes, dictionary) {
        Ok(req) => req,
        Err(e) => {
            error!(action = "radius_parse", status = "failed", error = ?e, "Malformed RADIUS packet");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Malformed RADIUS packet"));
        }
    };

    // 2. Extract Identifier to correlate requests in audit logs (PCI DSS 4.0 / NIST AU-2)
    let identifier = request.id();
    
    debug!(
        action = "radius_process",
        packet_type = ?request.code(),
        identifier = identifier,
        "Processing RADIUS request"
    );

    // 3. Create a default Least-Privilege Response (Access-Reject)
    let mut response = request.create_response(TypeCode::AccessReject);

    // --- INTEGRATION POINT ---
    // Inject your backend authentication logic here (e.g., database lookup, LDAP).
    // If authentication is successful, change the response code:
    // response.set_code(TypeCode::AccessAccept);
    // -------------------------

    info!(
        action = "radius_auth_decision",
        identifier = identifier,
        decision = ?response.code(),
        "Authentication decision generated"
    );

    // 4. Pack the response back into bytes using the RFC 6614 mandated secret
    match response.to_bytes(dictionary, RADSEC_SHARED_SECRET.as_bytes()) {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            error!(action = "radius_pack", status = "failed", error = ?e, "Failed to encode response");
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to encode RADIUS response"))
        }
    }
}
