use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub max_connections_per_sec: u32,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TlsConfig {
    pub client_ca_path: String,
    pub server_cert_path: String,
    pub private_key_path: String,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}

/// Enforces STIG / PCI DSS requirement: Private keys must not be readable by others.
pub fn verify_file_permissions(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    // Check if group or other have any read/write/execute permissions
    if mode & 0o077 != 0 {
        return Err(format!(
            "Insecure permissions ({:o}) on private key: {}. Must be 0600 or 0400.",
            mode, path
        )
        .into());
    }
    Ok(())
}
