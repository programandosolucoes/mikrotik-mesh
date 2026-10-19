# Especificação Técnica dos Protocolos

Este documento detalha o layout de pacotes, bytes, endianness e máquinas de estado implementadas na suíte **mikrotik-mesh**.

---

## 1. EoIP (Ethernet over IP - MikroTik)

O protocolo EoIP da MikroTik encapsula frames Ethernet de Camada 2 dentro de pacotes IP usando o protocolo **GRE (IP Protocol 47)** com flags específicas baseadas no padrão RFC 1701.

### Layout do Cabeçalho GRE/EoIP (8 Bytes)

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

* **Flags & Version (`0x2001`):** Flag `0x2000` (Key Present) + Versão GRE `0x0001`.
* **Protocol Type (`0x6400`):** Identificador específico da MikroTik indicando frame Ethernet bruto encapsulado.
* **Frame Length (Big Endian):** Comprimento em bytes do frame Ethernet interno.
  * **Keepalive:** Quando `frame_length == 0`, o pacote é interpretado pelo RouterOS como um keepalive (sem payload após o cabeçalho).
* **Tunnel ID (Little Endian):** Identificador numérico configurado em ambas as pontas.

---

## 2. MAC-Telnet (MikroTik Layer 2 Terminal)

O protocolo MAC-Telnet transporta sessões de terminal interativas sobre frames Ethernet / datagramas UDP endereçados à porta **`20561`**.

### Layout do Cabeçalho MAC-Telnet (22 Bytes) em ASCII

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

### Detalhamento dos Campos e Offsets

```text
Offset (Bytes)  Tamanho   Campo                 Descrição
0               1 Byte    Versão                Sempre 0x01
1               1 Byte    Tipo de Pacote        0x00=Data, 0x01=StartSession/SYN, 0x02=Ack, 0x03=EndSession/FIN, 0x04=Ping, 0x05=PingReply, 0xFF=Control
2..7            6 Bytes   Source MAC            MAC de origem da interface do cliente/servidor
8..13           6 Bytes   Destination MAC       MAC do dispositivo de destino
14..15          2 Bytes   Session ID            Identificador único da sessão (Big Endian)
16..17          2 Bytes   Client Type           Flags / Tipo de cliente (0x0000 para terminal MikroTik padrão)
18..21          4 Bytes   Sequence Number       Contador sequencial incremental de pacotes (Big Endian)
22+             Var       Payload               Dados interativos do terminal ou credenciais/desafio EC-SRP5
```

---

## 3. MNDP (MikroTik Neighbor Discovery Protocol)

Opera via broadcast na porta UDP **`5678`** (e porta `20561`). O pacote inicia com 4 bytes de controle, seguidos por blocos TLV (*Type-Length-Value*):

| TLV Type (u16) | Significado | Formato |
| :--- | :--- | :--- |
| `0x0001` | MAC Address | 6 bytes binários |
| `0x0005` | Identity (Nome do Roteador) | String UTF-8 |
| `0x0007` | Versão do RouterOS | String UTF-8 (ex: "7.16") |
| `0x0008` | Plataforma | String UTF-8 (ex: "MikroTik" / "Linux") |
| `0x000A` | Uptime do Sistema | 4 bytes Big-Endian (segundos) |
| `0x000C` | Modelo / Board Name | String UTF-8 (ex: "CHR" / "x86_64") |
| `0x0010` | Nome da Interface | String UTF-8 (ex: "ether1") |

---

## 4. Encapsulamento de Streaming sobre HTTPS TCP 443

Para permitir que túneis EoIP e conexões MAC-Telnet atravessem redes corporativas restritas, CGNAT e servidores web (XAMPP / Hostinger) que só permitem tráfego na porta 443, a suíte implementa um enquadramento binário de streaming:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic 'MK'           |  Proto Type   |   Tunnel ID   |
|         (0x4D 0x4B)           | (1=EoIP,2=Tel)|  (Big Endian) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length          |           Payload...          |
|        (Big Endian)           | (Frame Ethernet ou Pacote Tel)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Esse enquadramento pode ser transportado via:
* **Conexão TCP direta na porta 443.**
* **WebSocket Binário (`wss://seu-dominio.com/mkt-vpn`).**
* **HTTP POST Streaming Chunked.**
