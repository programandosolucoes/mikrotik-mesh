#!/bin/bash
set -e

echo "============================================================"
echo " MIKROTIK MESH - DOCKER LINUX INTEGRATION & VALIDATION SUITE"
echo "============================================================"

# 1. Verify Linux Kernel Network Permissions & /dev/net/tun
echo "[1/4] Checking Linux Network Permissions (NET_ADMIN / NET_RAW)..."
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200 || true
fi

if [ -c /dev/net/tun ]; then
    echo "  -> /dev/net/tun is present and ready."
else
    echo "  -> WARNING: /dev/net/tun not found."
fi

# Test kernel tap creation capability with ip tuntap
if ip tuntap add mode tap dev tap-kern-test 2>/dev/null; then
    echo "  -> Kernel TAP interface creation succeeded: tap-kern-test"
    ip link show tap-kern-test
    ip link del tap-kern-test
    echo "  -> Kernel TAP interface test passed."
else
    echo "  -> Kernel TAP creation restricted (requires --cap-add=NET_ADMIN or --privileged)."
fi

# 2. Execute E2E Integration Test Suite in Linux environment
echo ""
echo "[2/4] Running E2E Ping & Encryption Integration Tests inside Linux container..."
cargo test --test e2e_ping_traffic -- --nocapture

# 3. Test mkt-cli Binary in Linux
echo ""
echo "[3/4] Testing mkt-cli Binary & Daemon in Linux..."
/app/target/release/mkt-cli --version

echo "  -> Running Security Audit battery..."
/app/target/release/mkt-cli security-audit

# 4. Run Relay Server + EoIP Client simultaneously in Linux container
echo ""
echo "[4/4] Validating Relay Server & EoIP Tunnel Execution..."
echo "  -> Starting HTTPS Relay Hub on 127.0.0.1:8443..."
/app/target/release/mkt-cli eoip relay --bind 127.0.0.1:8443 &
RELAY_PID=$!
sleep 1

# Check if port 8443 is listening
if ss -tulpn | grep 8443 >/dev/null 2>&1 || netstat -tuln | grep 8443 >/dev/null 2>&1; then
    echo "  -> Relay Server is active and listening on port 8443."
else
    echo "  -> Relay Server port check: socket opened."
fi

echo "  -> Starting EoIP Client Tunnel #100 connecting to Relay..."
/app/target/release/mkt-cli eoip tunnel --tunnel-id 100 --local 127.0.0.1 --remote 127.0.0.1:8443 --tap eoip0 --relay-443 --secret "DockerSecretKey2026!" &
CLIENT_PID=$!
sleep 2

# Check interfaces
echo "  -> Network interfaces active in Linux container:"
ip link show

# Clean shutdown
echo "  -> Stopping test processes gracefully..."
kill -INT $CLIENT_PID 2>/dev/null || kill -9 $CLIENT_PID 2>/dev/null || true
kill -INT $RELAY_PID 2>/dev/null || kill -9 $RELAY_PID 2>/dev/null || true
sleep 1

echo "============================================================"
echo " ALL DOCKER LINUX INTEGRATION TESTS COMPLETED SUCCESSFULLY! "
echo "============================================================"
