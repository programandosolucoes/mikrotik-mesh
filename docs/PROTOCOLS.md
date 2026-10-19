# Technical Protocol Specifications

This document details the packet layouts, byte offsets, endianness, and state machines implemented in the **mikrotik-mesh** suite.

---

## 1. EoIP (Ethernet over IP - MikroTik)

The MikroTik EoIP protocol encapsulates Layer 2 Ethernet frames inside IP packets using **GRE (IP Protocol 47)** with specific header flags based on RFC 1701.

### GRE/EoIP Header Layout (8 Bytes)

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

* **Flags & Version (`0x2001`):** Flag `0x2000` (Key Present) + GRE Version `0x0001`.
* **Protocol Type (`0x6400`):** Specific MikroTik identifier indicating an encapsulated raw Ethernet frame.
* **Frame Length (Big Endian):** Byte length of the inner Ethernet frame.
  * **Keepalive:** When `frame_length == 0`, the packet is parsed by RouterOS as a keepalive (no payload following header).
* **Tunnel ID (Little Endian):** Numeric identifier configured on both endpoints.

---

## 2. MAC-Telnet (MikroTik Layer 2 Terminal)

The MAC-Telnet protocol carries interactive terminal sessions over Ethernet frames / UDP datagrams addressed to UDP port **`20561`**.

### MAC-Telnet Header Layout (22 Bytes)

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

### Packet Types:
- `0x00`: Data / SRP Handshake payload.
- `0x01`: StartSession (SYN) - Initiates terminal handshake.
- `0x02`: EndSession (FIN) - Closes session.
- `0x03`: Ack - Sequence acknowledgement.
- `0xFF`: Control / Reject.

---

## 3. MNDP (MikroTik Neighbor Discovery Protocol)

Operates via UDP broadcast to port `5678`. Transmits TLV (Type-Length-Value) attributes to discover active MikroTik routers on the network:
- `0x0001`: MAC Address (6 Bytes).
- `0x0005`: Identity / Hostname (ASCII).
- `0x0007`: RouterOS Version (ASCII).
- `0x0008`: Hardware Platform / Board Name (ASCII).
- `0x0010`: Interface Name (ASCII).
- `0x0011`: IPv4 Address (4 Bytes, Big Endian).

---

## 4. HTTPS TCP 443 Streaming Multiplexing

For CGNAT traversal and restricted VPS hosting, frames are encapsulated into a 6-byte prefix header over TCP:
```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic 'MK'           |  Proto Type   |   Tunnel ID   |
|         (0x4D 0x4B)           | (1=EoIP,2=Tel)|  (Big Endian) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length          |           Payload...          |
|        (Big Endian)           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
