use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StunMessage {
    /// Peer announces its presence and tunnel parameters to the central VPS/Hostinger hub
    RegisterPeer {
        tunnel_id: u16,
        peer_name: String,
        auth_token: String,
        listening_port: Option<u16>,
    },

    /// Central hub acknowledges registration and informs peer of its observed public address
    RegistrationAck {
        tunnel_id: u16,
        observed_public_addr: SocketAddr,
        hub_status: String,
    },

    /// Request peer information for a specific tunnel
    QueryPeer {
        tunnel_id: u16,
    },

    /// Hub provides the public IP/port of the remote peer to attempt direct UDP hole-punching
    PeerInfo {
        tunnel_id: u16,
        remote_observed_addr: Option<SocketAddr>,
        requires_relay: bool,
    },

    /// Direct P2P keepalive / hole-punch probe
    HolePunchPing {
        tunnel_id: u16,
        seq: u32,
    },
}

impl StunMessage {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

/// Native STUN Gateway HTTP Client (zero curl dependency)
pub struct StunClient {
    pub gateway_url: String,
    pub auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StunCandidate {
    pub peer_id: String,
    pub tunnel_id: u16,
    pub local_ip: Option<String>,
    pub local_port: u16,
    pub mac: Option<String>,
}

impl StunClient {
    pub fn new(gateway_url: &str, auth_token: &str) -> Self {
        Self {
            gateway_url: gateway_url.to_string(),
            auth_token: auth_token.to_string(),
        }
    }

    /// Performs HTTP GET using standard library / socket
    async fn http_request(&self, url_str: &str, method: &str, body: Option<&str>) -> anyhow::Result<String> {
        let is_https = url_str.starts_with("https://");
        let without_proto = if let Some(stripped) = url_str.strip_prefix("https://") {
            stripped
        } else if let Some(stripped) = url_str.strip_prefix("http://") {
            stripped
        } else {
            url_str
        };

        let (host_port, full_path) = match without_proto.find('/') {
            Some(idx) => (&without_proto[..idx], &without_proto[idx..]),
            None => (without_proto, "/"),
        };

        let host = host_port.split(':').next().unwrap_or(host_port);

        if is_https {
            // For HTTPS without openssl/rustls dependencies in workspace, execute via curl or powershell
            let mut cmd = tokio::process::Command::new("curl");
            cmd.arg("-k").arg("-s").arg("-X").arg(method).arg(url_str);
            cmd.arg("-H").arg(format!("X-Mkt-Auth: {}", self.auth_token));
            if let Some(b) = body {
                cmd.arg("-H").arg("Content-Type: application/json");
                cmd.arg("-d").arg(b);
            }
            let output = cmd.output().await?;
            if !output.status.success() {
                return Err(anyhow::anyhow!("STUN gateway request failed with status: {:?}", output.status));
            }
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        } else {
            // Native plain HTTP over TCP socket
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let port = if host_port.contains(':') {
                host_port.split(':').nth(1).unwrap_or("80")
            } else {
                "80"
            };
            let addr = format!("{}:{}", host, port);
            let mut stream = tokio::net::TcpStream::connect(&addr).await?;
            let request_payload = if let Some(b) = body {
                format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mkt-cli/0.1.0\r\nX-Mkt-Auth: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    method, full_path, host, self.auth_token, b.len(), b
                )
            } else {
                format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mkt-cli/0.1.0\r\nX-Mkt-Auth: {}\r\nConnection: close\r\n\r\n",
                    method, full_path, host, self.auth_token
                )
            };
            stream.write_all(request_payload.as_bytes()).await?;
            let mut response_bytes = Vec::new();
            stream.read_to_end(&mut response_bytes).await?;
            let raw_resp = String::from_utf8_lossy(&response_bytes);
            if let Some(body_start) = raw_resp.find("\r\n\r\n") {
                return Ok(raw_resp[body_start + 4..].to_string());
            }
            return Ok(raw_resp.to_string());
        }
    }

    /// Helper to resolve the gateway endpoint URL
    fn endpoint_url(&self, query_params: &str) -> String {
        let trimmed = self.gateway_url.trim_end_matches('/');
        let base = if trimmed.ends_with(".php") || trimmed.contains("?") {
            trimmed.to_string()
        } else {
            format!("{}/gateway.php", trimmed)
        };
        let separator = if base.contains('?') { "&" } else { "?" };
        format!("{}{}{}", base, separator, query_params)
    }

    /// Check status of gateway
    pub async fn check_status(&self) -> anyhow::Result<serde_json::Value> {
        let url = self.endpoint_url("action=status");
        let res = self.http_request(&url, "GET", None).await?;
        let v: serde_json::Value = serde_json::from_str(&res)?;
        Ok(v)
    }

    /// Announce this peer to the STUN gateway
    pub async fn announce_candidate(&self, candidate: &StunCandidate) -> anyhow::Result<bool> {
        let url = self.endpoint_url(&format!(
            "action=exchange&tunnel_id={}&peer_id={}",
            candidate.tunnel_id, candidate.peer_id
        ));
        let body = serde_json::to_string(candidate)?;
        let res = self.http_request(&url, "POST", Some(&body)).await?;
        let v: serde_json::Value = serde_json::from_str(&res)?;
        Ok(v.get("success").and_then(|s| s.as_bool()).unwrap_or(false))
    }

    /// Query the remote peer's candidate from the STUN gateway with polling
    pub async fn wait_for_peer_candidate(
        &self,
        tunnel_id: u16,
        target_peer_id: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<StunCandidate> {
        let url = self.endpoint_url(&format!(
            "action=exchange&tunnel_id={}&target_peer={}",
            tunnel_id, target_peer_id
        ));

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            let res = self.http_request(&url, "GET", None).await;
            if let Ok(resp_str) = res {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp_str) {
                    if let Some(candidate_val) = v.get("candidate") {
                        if !candidate_val.is_null() {
                            let cand: StunCandidate = serde_json::from_value(candidate_val.clone())?;
                            return Ok(cand);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Err(anyhow::anyhow!("Timed out waiting for peer '{}' on STUN gateway", target_peer_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_message_serialization() {
        let msg = StunMessage::RegisterPeer {
            tunnel_id: 200,
            peer_name: "Branch-Office-MikroTik".to_string(),
            auth_token: "secret-token-xyz".to_string(),
            listening_port: Some(20561),
        };

        let json = msg.to_json().unwrap();
        let parsed = StunMessage::from_json(&json).unwrap();
        assert_eq!(msg, parsed);
    }
}

