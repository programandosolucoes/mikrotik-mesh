# MikroTik Mesh Suite (Rust)

[![Language](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Tradução](https://img.shields.io/badge/Tradução-Português-green.svg)](README.pt-BR.md)
[![Rust](https://img.shields.io/badge/Rust-1.80+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)

A pure, modular, high-performance **Rust** implementation of **MikroTik Layer 2 protocols**: **MAC-Telnet** (client and server), **MNDP** (neighbor discovery), and **EoIP (Ethernet over IP)** tunnels, featuring **HTTPS TCP 443 encapsulation** and native **PHP (FFI / .so / .dll)** extension support.

---

## 🌟 Key Highlights

1. **Zero Kernel Modules:** Operates 100% in userspace via virtual TAP interfaces. No external kernel driver compilation required on Linux or Windows.
2. **RouterOS v7 & Legacy Support:**
   - Modern **EC-SRP5** (*Elliptic Curve Secure Remote Password* with Curve25519 and SHA-256) in constant time with memory zeroization for RouterOS v7.
   - Legacy MD5 challenge-response authentication for RouterOS v4, v5, and early v6.
3. **HTTPS TCP 443 Encapsulation:** Allows EoIP and MAC-Telnet traffic to traverse CGNAT, strict corporate firewalls, and operate on **restricted VPS (Hostinger)**, **cPanel**, or standard **XAMPP / Apache / Nginx** web hosting environments.
4. **PHP C-ABI Extension (.so / .dll):** Native C-ABI shared library with an out-of-the-box PHP wrapper class (`MikrotikVpnManager.php`) and gateway (`gateway.php`) to manage routes, tunnels, and remote wakeups from web panels.
5. **Dynamic STUN Gateway & CLI Parity:** Full NAT traversal without hardcoded tokens. Access tokens are dynamically issued by the web panel with tunnel-level isolation and timing-attack protection.
6. **Integrated Cybersecurity Battery:** Automated verification against timing attacks, RAM secret leaks, and fuzzing against malformed/corrupted packets.

---

## 🏗️ Workspace Architecture

* [`crates/mkt-proto`](crates/mkt-proto): Zero-copy parsers and serializers for MAC-Telnet, EoIP (GRE `0x6400`), MNDP, and Ethernet frames.
* [`crates/mkt-crypto`](crates/mkt-crypto): Cryptographic engine for EC-SRP5 (Curve25519 / SHA-256), legacy MD5 fallback, and ChaCha20-Poly1305 AEAD tunnel encryption.
* [`crates/mkt-net`](crates/mkt-net): Virtual TAP abstractions, raw GRE sockets (IP protocol 47), UDP sockets, HTTPS TCP 443 streaming transport, and native STUN client.
* [`crates/mkt-core`](crates/mkt-core): Session state machines, bidirectional tunnel management, MAC filtering, and route dispatch.
* [`crates/mkt-php`](crates/mkt-php): C-ABI shared library (`libmkt_php.so` / `mkt_php.dll`).
* [`crates/mkt-cli`](crates/mkt-cli): Unified CLI binary for terminal access, tunnels, STUN discovery, and security audits.
* [`php/`](php): Web dashboard (`index.php`), gateway endpoint (`gateway.php`), token manager (`TokenStore.php`), and PHP class (`MikrotikVpnManager.php`).

---

## 📦 Packet Diagrams (ASCII Frame Layouts)

### 1. MikroTik EoIP / GRE Packet (RFC 1701 + EtherType 0x6400)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   GRE FLAGS   |  RESERVED/VER |         Protocol Type         |
|   (0x20 0x01)                 |            (0x6400)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Encapsulated Frame Length   |           Tunnel ID           |
|         (Big Endian)          |        (Little Endian)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Ethernet Frame...                     |
|  (Dst MAC: 6B, Src MAC: 6B, EtherType: 2B, Payload: 46-1500B)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2. MikroTik MAC-Telnet Packet (22-Byte Header)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |  Packet Type  |          Source MAC           |
|     (0x01)    | (0=Data,1=SYN)|          (Bytes 0..1)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source MAC                            |
|                        (Bytes 2..5)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Destination MAC                         |
|                        (Bytes 0..3)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Destination MAC         |          Session ID           |
|        (Bytes 4..5)           |         (Big Endian)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Client Type          |        Sequence Number        |
|        (0x0000=Terminal)      |          (Bytes 0..1)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Sequence Number        |          Payload...           |
|          (Bytes 2..3)         | (Terminal text or SRP proof)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Payload...                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3. Multiplexed Streaming Frame over HTTPS TCP 443
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic 'MK'           |  Proto Type   |   Tunnel ID   |
|         (0x4D 0x4B)           | (1=EoIP,2=Tel)|  (Big Endian) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length          |           Payload...          |
|        (Big Endian)           | (Ethernet Frame or Tel Packet)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 🚀 Building and Testing

### Compile the Workspace
```bash
cargo build --release
```

### Run Automated Test Suite (32 Tests Passing)
```bash
cargo test
```

### Run Built-in Cybersecurity Audit
```bash
cargo run -p mkt-cli -- security-audit
```

---

## 📖 CLI Usage (`mkt-cli`)

### 1. MAC-Telnet Operations
```bash
# Connect to RouterOS via MAC address:
mkt-cli mactelnet connect 00:0C:42:1F:2A:3B -u admin -p MySecretPassword

# Discover MikroTik devices on the local network via MNDP:
mkt-cli mactelnet scan --timeout 5

# Start a Linux pseudo-terminal server accessible via MikroTik MAC-Telnet:
mkt-cli mactelnet server --mac 00:11:22:33:44:55 -u admin -p MyPassword
```

### 2. EoIP Tunnels & TCP 443 Relay
```bash
# Connect directly to a MikroTik router using native raw GRE (IP Protocol 47):
mkt-cli eoip tunnel --tunnel-id 100 --remote 192.168.88.1 --tap eoip0

# Connect over HTTPS TCP 443 relay (to bypass CGNAT / strict firewalls):
mkt-cli eoip tunnel --tunnel-id 100 --remote vps.mydomain.com:443 --tap eoip0 --relay-443

# Start the Central Relay Hub on a VPS (listening on port 443):
mkt-cli eoip relay --bind 0.0.0.0:443
```

---

## 🛰️ STUN Gateway & Automated Peer Discovery

For nodes behind symmetric NAT or CGNAT, the suite includes automated STUN signaling directly inside `mkt-cli`:

* **Official Default Endpoint:** `https://carloslopes.programandosolucoes.com.br/mesh/gateway.php`
* **Custom STUN Servers:** Any organization can host their own `gateway.php` and supply `--stun-url` and `--stun-token`.
* **Zero Hardcoded Secrets:** Authentication tokens are issued dynamically from the web panel and passed via `--stun-token` or the `MKT_STUN_TOKEN` environment variable.

### 1. Starting an EoIP Tunnel with STUN Auto-Discovery:
```bash
# At Peer A (Home):
mkt-cli eoip tunnel --tunnel-id 500 --stun \
  --stun-url "https://my-domain.com/mesh/gateway.php" \
  --stun-token "mkt_tok_d8a7c2b3e4f5..." \
  --peer-id node_a --target-peer node_b --tap eoip0

# At Peer B (Branch Office):
mkt-cli eoip tunnel --tunnel-id 500 --stun \
  --stun-url "https://my-domain.com/mesh/gateway.php" \
  --stun-token "mkt_tok_d8a7c2b3e4f5..." \
  --peer-id node_b --target-peer node_a --tap eoip0
```

### 2. STUN Diagnostic Commands:
```bash
# Check STUN gateway status:
mkt-cli eoip stun status --url "https://my-domain.com/mesh/gateway.php" --token "mkt_tok_..."

# Manually publish candidate and wait for peer:
mkt-cli eoip stun exchange --url "https://my-domain.com/mesh/gateway.php" --token "mkt_tok_..." \
  --tunnel-id 500 --peer-id node_a --target-peer node_b
```

---

## ⚡ Fast Remote Wakeup (PS5 & Wake-on-LAN)

```bash
# Wake PlayStation 5 in Rest Mode over VPN/LAN (UDP 9302):
mkt-cli wakeup ps5 10.10.10.50 --credential "-394857201"

# Send standard Wake-on-LAN Magic Packet:
mkt-cli wakeup wol 00:11:22:33:44:55 --broadcast 255.255.255.255:9
```

---

## 🌐 PHP & Web Panel Integration

To deploy on any Apache, Nginx, XAMPP, or cPanel environment:
1. Copy the compiled library (`target/release/libmkt_php.so` or `mkt_php.dll`) to your PHP project.
2. Ensure the `ffi` extension is enabled in `php.ini` (`extension=ffi`).
3. Open `php/index.php` in your browser. The web dashboard provides:
   - Full bilingual interface (English default, one-click switch to Portuguese).
   - Live tunnel management and MAC filter controls.
   - Dynamic STUN access token generation with tunnel isolation.
   - 1-click PlayStation 5 network discovery and wakeup.

```php
require_once __DIR__ . '/php/MikrotikVpnManager.php';

$vpn = new MikrotikVpnManager();
$vpn->addRoute(100, "MikroTik-Headquarters", "187.x.x.x:443", true);

$routes = $vpn->listRoutes();
print_r($routes);
```

---

## 🧪 Automated Integration Tests (`tests/`)

- **`tests/e2e_ping_traffic.rs`**:
  - Full bidirectional L2 data-plane traffic over Relay Hub in plaintext and ChaCha20-Poly1305 AEAD.
  - 10-packet ICMP ping burst measuring minimum, average, and maximum RTT with 0% packet loss.
  - Active MAC allowlist enforcement and unauthorized packet drops.
- **`tests/legacy_and_stun_integration.rs`**:
  - Real STUN candidate exchange and coordination between multiple Linux nodes.
  - Legacy MikroTik RouterOS v4/v5 MD5 challenge-response authentication (`md5(0x00 + password + challenge)`).
  - Plaintext interactive MAC-Telnet terminal sessions.

Run all tests:
```bash
cargo test
```

---

## 📄 License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
