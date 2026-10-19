# VPS Deployment Guide (Hostinger) & Shared Hosting (XAMPP / Apache)

This guide explains how to deploy the **mikrotik-mesh** suite on a **Hostinger VPS** (KVM or Ubuntu/Debian) or Shared Web Hosting (XAMPP/Apache/Nginx) to operate as a Central VPN & STUN Hub.

---

## 1. Why Port 443 (HTTPS TCP)?

In shared hosting providers or firewalled VPS instances:
* **Raw GRE Protocol (IP 47):** Often lacks NAT support on residential ISPs or is blocked by hosting firewalls.
* **Arbitrary UDP Ports:** Frequently restricted by provider security policies.
* **Port 443 (HTTPS TCP):** Is **universally open**, passing through any firewall, reverse proxy (Nginx, Cloudflare), or ISP CGNAT.

The suite encapsulates Layer 2 frames (EoIP and MAC-Telnet) inside an HTTPS TCP stream on port 443.

---

## 2. Step-by-Step Installation on Hostinger VPS (KVM / Linux)

### Step 1: Clone and Compile the Project
On your Linux VPS (Ubuntu/Debian):
```bash
sudo apt update && sudo apt install -y build-essential git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

git clone https://github.com/programandosolucoes/mikrotik-mesh.git
cd mikrotik-mesh
cargo build --release
```

### Step 2: Run Central Relay Server on Port 443
```bash
# Starts the central relay listening on port 443
sudo ./target/release/mkt-cli eoip relay --bind 0.0.0.0:443
```

---

## 3. Shared Hosting / XAMPP with PHP

If you are using a standard web server with PHP (Apache/XAMPP):

1. Copy the compiled shared library:
   * Linux: `target/release/libmkt_php.so` to your web root or `/usr/local/lib/`.
   * Windows: `target/release/mkt_php.dll` to your XAMPP `htdocs` directory.
2. Ensure the `ffi` extension is enabled in `php.ini`:
   ```ini
   extension=ffi
   ffi.enable=true
   ```
3. Copy the files [`php/MikrotikVpnManager.php`](../php/MikrotikVpnManager.php), [`php/gateway.php`](../php/gateway.php), [`php/TokenStore.php`](../php/TokenStore.php), and [`php/index.php`](../php/index.php) to your server.

### Testing the Gateway API via cURL
Generate an access token in the web dashboard (`index.php`), then:
```bash
# Query gateway status:
curl -H "X-Mkt-Auth: <YOUR_TOKEN>" https://your-domain.com/gateway.php?action=status

# Register an EoIP tunnel endpoint:
curl -X POST -H "Content-Type: application/json" \
     -H "X-Mkt-Auth: <YOUR_TOKEN>" \
     -d '{"tunnel_id": 100, "peer_name": "Mikrotik-Office", "listening_port": 443}' \
     https://your-domain.com/gateway.php?action=register
```

---

## 4. Connecting the Remote Client Node

On the remote client machine (Linux or Windows):
```bash
# Connect to your VPS over port 443 and create local virtual interface eoip0:
sudo mkt-cli eoip tunnel --tunnel-id 100 --remote vps.yourdomain.com:443 --tap eoip0 --relay-443

# Assign an IP address to the local virtual interface:
sudo ip addr add 10.10.10.2/24 dev eoip0
sudo ip link set eoip0 up
```

The `eoip0` interface is now bridged in Layer 2 with the other side of the tunnel, exactly as if connected to the same physical switch!
