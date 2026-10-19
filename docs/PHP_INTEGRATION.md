# PHP, XAMPP, and Web Panel Integration Guide

This document explains how to use the **`mkt-php`** native library (`libmkt_php.so` / `mkt_php.dll`) and the [`php/MikrotikVpnManager.php`](../php/MikrotikVpnManager.php) class in modern PHP projects (PHP 8.1+).

---

## 1. PHP Requirements

1. PHP 8.1 or higher (CLI or FPM).
2. The **`FFI`** extension enabled in your `php.ini`:
   ```ini
   extension=ffi
   ffi.enable=true
   ```

---

## 2. Compiling the Dynamic Shared Library

To compile the `.so` (on Linux) or `.dll` (on Windows):

```bash
cargo build --release -p mkt-php
```

The resulting binaries will be placed in:
* **Linux:** `target/release/libmkt_php.so`
* **Windows:** `target/release/mkt_php.dll`

---

## 3. Practical PHP Example

### Managing EoIP Tunnels and Routes

```php
<?php
require_once __DIR__ . '/php/MikrotikVpnManager.php';

try {
    // Initialize FFI manager pointing to compiled library
    $manager = new MikrotikVpnManager();
    echo "Rust Engine Version: " . MikrotikVpnManager::getVersion() . PHP_EOL;

    // 1. Register an EoIP tunnel for a remote MikroTik
    $tunnelId = 1500;
    $peerName = "Branch-SaoPaulo";
    $endpoint = "187.55.120.30:443"; // Connected over HTTPS 443 relay

    $ok = $manager->addRoute($tunnelId, $peerName, $endpoint, true);
    echo $ok ? "Tunnel #$tunnelId registered successfully!" : "Failed to register tunnel";
    echo PHP_EOL;

    // 2. List active tunnels and routes
    $routes = $manager->listRoutes();
    foreach ($routes as $route) {
        echo sprintf(
            "Tunnel ID: %d | Peer: %s | Endpoint: %s | Relay: %s\n",
            $route['tunnel_id'],
            $route['peer_name'],
            $route['endpoint'] ?? 'Awaiting TCP',
            $route['relay'] ? 'YES' : 'NO'
        );
    }

    // 3. Set allowed MAC filter
    $manager->setMacFilter($tunnelId, "00:D9:D1:11:22:33,00:D9:D1:44:55:66");

} catch (\Throwable $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
}
```

### Remote Wakeup (PlayStation 5 & Wake-on-LAN)

```php
// Wake a PlayStation 5 in Rest Mode over VPN/LAN (UDP 9302):
$manager->sendPs5Wakeup("10.10.10.50", "-394857201");

// Send standard Wake-on-LAN Magic Packet:
$manager->sendWol("00:11:22:33:44:55", "255.255.255.255:9");
```

---

## 4. Web Dashboard (`php/index.php`)

A full web dashboard is included in [`php/index.php`](../php/index.php), providing:
- Bilingual interface (English default, one-click switch to Portuguese).
- Real-time tunnel status and route management.
- Dynamic STUN access token generation with tunnel isolation.
- Fast wakeup controls for PS5 and Wake-on-LAN devices.
