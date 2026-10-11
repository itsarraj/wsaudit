use std::time::Duration;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::report::{AuditReport, Finding, Severity};

pub async fn run_security_audit(target_url: &str) -> Result<AuditReport> {
    let mut report = AuditReport::new(target_url.to_string());
    let url = Url::parse(target_url).context("Invalid WebSocket URL")?;

    // 1. Check Transport Security
    check_transport_security(&url, &mut report);

    // 2. Check CSWSH: Arbitrary Attacker Origin
    let _ = probe_origin(
        &url,
        Some("https://evil-attacker.example.com"),
        "cswsh_arbitrary_origin",
        "Cross-Site WebSocket Hijacking (Arbitrary Origin)",
        Severity::High,
        "Server completed WebSocket handshake for untrusted origin (https://evil-attacker.example.com). Any website visited by authenticated users can hijack the socket.",
        "Validate the Origin header during the HTTP Upgrade handshake against a strict allowlist.",
        &mut report,
    )
    .await;

    // 3. Check CSWSH: Null Origin
    let _ = probe_origin(
        &url,
        Some("null"),
        "cswsh_null_origin",
        "Cross-Site WebSocket Hijacking (Null Origin)",
        Severity::Medium,
        "Server completed WebSocket handshake with Origin: null. Sandboxed iframes and local contexts can bypass origin controls.",
        "Reject Origin: null handshakes in production.",
        &mut report,
    )
    .await;

    // 4. Check CSWSH: Subdomain / Suffix Spoofing
    let host = url.host_str().unwrap_or("target.com");
    let spoof_origin = format!("https://{host}.attacker-probe.example.com");
    let _ = probe_origin(
        &url,
        Some(&spoof_origin),
        "cswsh_subdomain_spoof",
        "Origin Domain Suffix / Subdomain Spoofing Bypass",
        Severity::High,
        &format!("Server accepted Origin: {spoof_origin}. Loose regex or substring matching is likely being used."),
        "Use strict URI parser and check host equality against exact domain names.",
        &mut report,
    )
    .await;

    // 5. Check RFC 6455 Client Masking Enforcement
    let _ = probe_client_masking(&url, &mut report).await;

    Ok(report)
}

fn check_transport_security(url: &Url, report: &mut AuditReport) {
    match url.scheme() {
        "wss" => {
            report.add(Finding {
                id: "transport_tls_enabled".to_string(),
                severity: Severity::Pass,
                title: "Encrypted Transport (TLS)".to_string(),
                description: "Target uses wss:// encrypted TLS transport.".to_string(),
                remediation: String::new(),
            });
        }
        "ws" => {
            let is_local = match url.host_str() {
                Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("0.0.0.0") => true,
                _ => false,
            };

            if is_local {
                report.add(Finding {
                    id: "transport_local_ws".to_string(),
                    severity: Severity::Pass,
                    title: "Loopback Unencrypted Transport".to_string(),
                    description: "Target uses ws:// on loopback address (permitted for local dev).".to_string(),
                    remediation: String::new(),
                });
            } else {
                report.add(Finding {
                    id: "insecure_transport_ws".to_string(),
                    severity: Severity::High,
                    title: "Unencrypted WebSocket Transport (ws://)".to_string(),
                    description: "Target uses unencrypted ws:// over non-loopback network. Traffic is vulnerable to interception and tampering.".to_string(),
                    remediation: "Deploy TLS and use wss:// scheme.".to_string(),
                });
            }
        }
        _ => {}
    }
}

async fn probe_origin(
    url: &Url,
    origin: Option<&str>,
    check_id: &str,
    title: &str,
    vuln_severity: Severity,
    vuln_desc: &str,
    remediation: &str,
    report: &mut AuditReport,
) -> Result<()> {
    let host = url.host_str().unwrap_or("127.0.0.1");
    let port = url.port().unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
    let addr = format!("{host}:{port}");

    let mut stream = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(()),
    };

    let path = if url.path().is_empty() { "/" } else { url.path() };
    let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
    let full_path = format!("{path}{query}");

    let origin_header = match origin {
        Some(o) => format!("Origin: {o}\r\n"),
        None => String::new(),
    };

    let req = format!(
        "GET {full_path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         {origin_header}\
         \r\n"
    );

    stream.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            // Connection closed or dropped without HTTP response -> safe
            report.add(Finding {
                id: format!("{check_id}_rejected"),
                severity: Severity::Pass,
                title: format!("{title} (Rejected)"),
                description: format!("Server dropped or rejected connection with origin {:?}", origin),
                remediation: String::new(),
            });
            return Ok(());
        }
    };

    let resp = String::from_utf8_lossy(&buf[..n]);
    let status_line = resp.lines().next().unwrap_or("");

    if status_line.contains("101") {
        // Upgrade accepted -> Vulnerability
        report.add(Finding {
            id: check_id.to_string(),
            severity: vuln_severity,
            title: title.to_string(),
            description: vuln_desc.to_string(),
            remediation: remediation.to_string(),
        });
    } else {
        // Non-101 response (e.g. 403 Forbidden, 400 Bad Request) -> Safe
        report.add(Finding {
            id: format!("{check_id}_rejected"),
            severity: Severity::Pass,
            title: format!("{title} (Rejected)"),
            description: format!("Server returned {status_line} for origin {:?}", origin),
            remediation: String::new(),
        });
    }

    Ok(())
}

async fn probe_client_masking(url: &Url, report: &mut AuditReport) -> Result<()> {
    let host = url.host_str().unwrap_or("127.0.0.1");
    let port = url.port().unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
    let addr = format!("{host}:{port}");

    let mut stream = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(()),
    };

    let path = if url.path().is_empty() { "/" } else { url.path() };
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );

    stream.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let resp = String::from_utf8_lossy(&buf[..n]);
    if !resp.lines().next().unwrap_or("").contains("101") {
        return Ok(());
    }

    // Handshake completed! Now send an UNMASKED frame:
    // Opcode 0x1 (Text), Fin=1 => 0x81
    // Mask bit = 0, length 5 => 0x05
    // Payload "hello" => [104, 101, 108, 108, 111]
    let unmasked_frame = [0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
    stream.write_all(&unmasked_frame).await?;

    // RFC 6455 Section 5.3: Server MUST close connection (Close code 1002 or TCP FIN)
    let reply = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await;

    match reply {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Connection closed or EOF
            report.add(Finding {
                id: "rfc6455_masking_enforced".to_string(),
                severity: Severity::Pass,
                title: "RFC 6455 Client Masking Enforced".to_string(),
                description: "Server correctly terminated connection upon receiving an unmasked client frame.".to_string(),
                remediation: String::new(),
            });
        }
        Ok(Ok(bytes_read)) => {
            // Check if server sent a Close frame (opcode 0x8) or processed frame
            let first_byte = buf[0];
            let opcode = first_byte & 0x0F;
            if opcode == 0x8 {
                // Close frame
                report.add(Finding {
                    id: "rfc6455_masking_enforced".to_string(),
                    severity: Severity::Pass,
                    title: "RFC 6455 Client Masking Enforced".to_string(),
                    description: "Server sent Close frame upon receiving unmasked client frame.".to_string(),
                    remediation: String::new(),
                });
            } else {
                // Server accepted or echoed the unmasked frame!
                report.add(Finding {
                    id: "rfc6455_unmasked_frame_accepted".to_string(),
                    severity: Severity::Medium,
                    title: "RFC 6455 Client Masking Not Enforced".to_string(),
                    description: format!("Server accepted an unmasked client frame (read {bytes_read} B response). Vulnerable to intermediary cache poisoning."),
                    remediation: "Ensure the WebSocket server enforces RFC 6455 Section 5.3 client frame masking.".to_string(),
                });
            }
        }
    }

    Ok(())
}
