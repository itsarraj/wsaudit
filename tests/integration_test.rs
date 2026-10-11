use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wsaudit::probes::run_security_audit;
use wsaudit::report::Severity;

async fn spawn_vulnerable_ws_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                // Vulnerable server: accepts any origin with 101 Switching Protocols
                let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                            Upgrade: websocket\r\n\
                            Connection: Upgrade\r\n\
                            Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                            \r\n";
                let _ = stream.write_all(resp.as_bytes()).await;

                // Keep connection open or echo
                let _ = stream.read(&mut buf).await;
            });
        }
    });

    addr
}

async fn spawn_secure_ws_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                // Check origin
                if req.contains("Origin: https://trusted.example.com") {
                    let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                                Upgrade: websocket\r\n\
                                Connection: Upgrade\r\n\
                                Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                                \r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    // Reject untrusted origin with 403 Forbidden
                    let resp = "HTTP/1.1 403 Forbidden\r\n\
                                Content-Type: text/plain\r\n\
                                Connection: close\r\n\
                                \r\n\
                                Forbidden Origin";
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn test_audit_flags_cswsh_vulnerability() {
    let addr = spawn_vulnerable_ws_server().await;
    let url = format!("ws://{addr}/ws");

    let report = run_security_audit(&url).await.unwrap();

    assert!(report.has_vulnerabilities());

    let cswsh = report
        .findings
        .iter()
        .find(|f| f.id == "cswsh_arbitrary_origin");
    assert!(cswsh.is_some(), "Expected cswsh_arbitrary_origin finding");
    assert_eq!(cswsh.unwrap().severity, Severity::High);

    let null_origin = report
        .findings
        .iter()
        .find(|f| f.id == "cswsh_null_origin");
    assert!(null_origin.is_some(), "Expected cswsh_null_origin finding");
    assert_eq!(null_origin.unwrap().severity, Severity::Medium);
}

#[tokio::test]
async fn test_audit_passes_strict_origin_server() {
    let addr = spawn_secure_ws_server().await;
    let url = format!("ws://{addr}/ws");

    let report = run_security_audit(&url).await.unwrap();

    let cswsh_rejected = report
        .findings
        .iter()
        .find(|f| f.id == "cswsh_arbitrary_origin_rejected");
    assert!(
        cswsh_rejected.is_some(),
        "Expected cswsh_arbitrary_origin_rejected finding"
    );
    assert_eq!(cswsh_rejected.unwrap().severity, Severity::Pass);

    let null_rejected = report
        .findings
        .iter()
        .find(|f| f.id == "cswsh_null_origin_rejected");
    assert!(
        null_rejected.is_some(),
        "Expected cswsh_null_origin_rejected finding"
    );
    assert_eq!(null_rejected.unwrap().severity, Severity::Pass);
}
