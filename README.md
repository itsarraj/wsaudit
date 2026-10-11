# wsaudit

Audits a live WebSocket endpoint for Cross-Site WebSocket Hijacking (CSWSH), unvalidated `Origin` headers, and RFC 6455 client frame masking compliance — the WebSocket security counterpart to [`corsaudit`](../corsaudit) and [`headersec`](../headersec).

Exit code `1` if any high- or medium-severity vulnerability is detected, suitable for CI/CD security gate checks.

---

## Why

Standard web application security scanners focus on HTTP request-response vulnerabilities (CORS, CSP, security headers). However, WebSockets introduce unique attack vectors:
1. **Cross-Site WebSocket Hijacking (CSWSH)**: When a browser establishes a WebSocket connection, it automatically includes ambient session cookies and HTTP authentication. If the server does not validate the `Origin` header during the HTTP Upgrade handshake, a malicious third-party site visited by the user can hijack the WebSocket connection, read live private data, and issue unauthorized commands.
2. **RFC 6455 Masking Violations**: RFC 6455 Section 5.3 strictly mandates that all client-to-server frames MUST be masked. Servers that accept unmasked client frames enable proxy cache poisoning attacks on intermediate HTTP proxies.
3. **Domain Suffix Spoofing**: Naive regex validation like `.*example.com` allows attackers to bypass origin checks with domains like `example.com.attacker.com` or `attacker-example.com`.

`wsaudit` probes for all of these automatically in a single CLI command.

---

## Installation

```sh
cargo install --path .
```

---

## Usage

### 1. Basic Audit

```sh
wsaudit ws://localhost:8080/socket
```

Sample report:
```text
=================== WebSocket Security Audit Report ===================
Target URL: ws://localhost:8080/socket
Checks Run: 5
Summary:    2 passed, 2 high/critical, 1 medium

[ PASS ] Loopback Unencrypted Transport [transport_local_ws]
       Target uses ws:// on loopback address (permitted for local dev).

[ HIGH ] Cross-Site WebSocket Hijacking (Arbitrary Origin) [cswsh_arbitrary_origin]
       Server completed WebSocket handshake for untrusted origin (https://evil-attacker.example.com). Any website visited by authenticated users can hijack the socket.
       Fix: Validate the Origin header during the HTTP Upgrade handshake against a strict allowlist.

[ MED ] Cross-Site WebSocket Hijacking (Null Origin) [cswsh_null_origin]
       Server completed WebSocket handshake with Origin: null. Sandboxed iframes and local contexts can bypass origin controls.
       Fix: Reject Origin: null handshakes in production.

[ HIGH ] Origin Domain Suffix / Subdomain Spoofing Bypass [cswsh_subdomain_spoof]
       Server accepted Origin: https://localhost.attacker-probe.example.com. Loose regex or substring matching is likely being used.
       Fix: Use strict URI parser and check host equality against exact domain names.

[ PASS ] RFC 6455 Client Masking Enforced [rfc6455_masking_enforced]
       Server correctly terminated connection upon receiving an unmasked client frame.

Result: VULNERABILITIES DETECTED (Exit code 1)
=======================================================================
```

---

### 2. CI/CD Automated Security Gate (JSON Output)

```sh
wsaudit https://staging-api.example.com/ws --json
```

---

## Rules Checked

| Rule ID | Severity | Description |
|---|---|---|
| `cswsh_arbitrary_origin` | **HIGH** | Server completes the WebSocket handshake when presented with an arbitrary, unrelated `Origin: https://evil-attacker.example.com`. |
| `cswsh_subdomain_spoof` | **HIGH** | Server accepts origins like `target.com.attacker.com` due to loose regex or substring validation. |
| `insecure_transport_ws` | **HIGH** | Target uses unencrypted `ws://` over a non-loopback network, exposing traffic to cleartext interception. |
| `cswsh_null_origin` | **MEDIUM** | Server accepts `Origin: null`, allowing exploitation from sandboxed iframes. |
| `rfc6455_unmasked_frame_accepted` | **MEDIUM** | Server accepts unmasked frames from clients, violating RFC 6455 Section 5.3 and exposing proxies to cache poisoning. |
| `transport_tls_enabled` | **PASS** | Target uses encrypted `wss://` transport. |
| `cswsh_rejected` | **PASS** | Server correctly returns 403 Forbidden or drops connections from untrusted origins. |
| `rfc6455_masking_enforced` | **PASS** | Server terminates connection upon receiving unmasked client frames per RFC 6455. |

---

## Status: built and verified against real WebSocket servers

- **1 unit test** (`cargo test --lib`):
  - Audit report severity calculation and vulnerability exit-code gating logic.

- **2 live integration tests** (`cargo test --test integration_test`):
  - **Vulnerable server test**: Built an independent real HTTP/WebSocket server that accepts any origin. Confirmed `wsaudit` correctly detects and flags `cswsh_arbitrary_origin` (HIGH) and `cswsh_null_origin` (MED), exiting with failure status.
  - **Strict origin server test**: Built an independent real server enforcing strict origin matching and returning HTTP 403 Forbidden to untrusted origins. Confirmed `wsaudit` marks the endpoint clean with `Severity::Pass`.
