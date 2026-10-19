# MikroTik CHR (RouterOS v7) Lab & Testing Guide

This guide explains how to spin up a virtual machine with **MikroTik RouterOS v7 CHR (Cloud Hosted Router)** to validate **MAC-Telnet** (client and server) and **EoIP tunnels** in a local lab environment.

---

## 1. Obtaining RouterOS v7 CHR for Free

MikroTik provides free CHR disk images. The "Free" mode limits the interface speed to 1 Mbps, which is more than sufficient for testing terminal sessions and L2 tunnel traffic.

```bash
# Download the raw disk image of RouterOS v7:
wget https://download.mikrotik.com/routeros/7.16/chr-7.16.img.zip
unzip chr-7.16.img.zip
```

---

## 2. Creating an Isolated L2 Network Segment with QEMU and TAP

To connect the RouterOS VM and your host machine on the same Layer 2 segment:

```bash
# 1. Create a virtual TAP interface on the Linux host:
sudo ip tuntap add mode tap dev tap-mkt
sudo ip link set tap-mkt up

# 2. Boot MikroTik CHR via QEMU attached to the TAP interface:
qemu-system-x86_64 -m 256M -smp 1 \
  -drive file=chr-7.16.img,format=raw \
  -netdev tap,id=net0,ifname=tap-mkt,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0,mac=00:0c:42:01:02:03 \
  -nographic
```

RouterOS will boot to the serial console. Log in with user `admin` and an empty password.

---

## 3. Test 1: Rust MAC-Telnet Client -> MikroTik Server

On your host machine:
```bash
# Discover neighbors via MNDP:
mkt-cli mactelnet scan --timeout 3
# Expected output: CHR discovered with MAC 00:0C:42:01:02:03

# Connect via MAC-Telnet to CHR:
mkt-cli mactelnet connect 00:0C:42:01:02:03 -u admin
```
The client automatically negotiates the **EC-SRP5** cryptographic handshake with RouterOS v7 and opens the interactive terminal session.

---

## 4. Test 2: MikroTik Client -> Rust MAC-Telnet Server

1. On your host machine, start the Rust MAC-Telnet server daemon:
   ```bash
   mkt-cli mactelnet server --mac 00:11:22:33:44:55 --user admin --pass secret123
   ```
2. Inside the MikroTik terminal, initiate MAC-Telnet to the Rust server:
   ```routeros
   /tool mac-telnet 00:11:22:33:44:55
   ```
3. Enter credentials `admin` / `secret123`.
4. You will gain shell access to the Linux host terminal directly from the MikroTik console!

---

## 5. Test 3: EoIP Tunnel between Host and MikroTik

1. In the MikroTik terminal, configure an EoIP tunnel:
   ```routeros
   /interface eoip add name=eoip1 tunnel-id=200 remote-address=192.168.100.1
   /ip address add address=10.200.0.1/24 interface=eoip1
   ```
2. On your host, start the EoIP tunnel with the same `tunnel-id=200`:
   ```bash
   sudo mkt-cli eoip tunnel --tunnel-id 200 --remote 192.168.100.2 --tap eoip0
   ```
3. Configure the IP address on the host TAP interface:
   ```bash
   sudo ip addr add 10.200.0.2/24 dev eoip0
   sudo ip link set eoip0 up
   ```
4. Test ping:
   ```bash
   ping -c 4 10.200.0.1
   ```
**Expected Outcome:** 100% of ping packets succeed through the userspace EoIP tunnel over native GRE!
