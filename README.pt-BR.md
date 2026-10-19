# MikroTik Mesh Suite (Rust)

Implementação em **Rust** puro, limpa e modular dos protocolos de Camada 2 da **MikroTik**: **MAC-Telnet** (cliente e servidor), **MNDP** (descoberta de vizinhos) e túneis **EoIP (Ethernet over IP)**, com suporte a **encapsulamento sobre HTTPS TCP 443** e extensão nativa para **PHP (FFI / .so / .dll)**.

---

## 🌟 Principais Destaques

1. **Zero Módulos de Kernel:** Opera 100% em espaço de usuário (*userspace*). Não requer compilação de drivers externos no Linux ou Windows.
2. **Compatível com RouterOS v7:** Implementa o protocolo criptográfico moderno **EC-SRP5** (*Elliptic Curve Secure Remote Password* com Curve25519 e SHA-256) em tempo constante e com zeroização segura de memória.
3. **Encapsulamento sobre HTTPS TCP 443:** Permite que o tráfego EoIP e MAC-Telnet atravesse CGNAT, firewalls corporativos e funcione perfeitamente em **VPS restritas (Hostinger)**, **cPanel** ou qualquer ambiente **XAMPP / Apache / Nginx**.
4. **Módulo PHP (.so / .dll):** Biblioteca nativa de alta performance C-ABI com classe PHP pronta (`MikrotikVpnManager.php`) e endpoint de gateway (`gateway.php`) para gerenciar rotas e túneis a partir de painéis web.
5. **Bateria de Cibersegurança Integrada:** Testes automatizados contra *timing attacks*, vazamento de chaves na RAM e fuzzing contra pacotes corrompidos.

---

## 🏗️ Estrutura do Workspace

* [`crates/mkt-proto`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-proto): Parsers e serializadores zero-copy para MAC-Telnet, EoIP (GRE `0x6400`), MNDP e frames Ethernet.
* [`crates/mkt-crypto`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-crypto): Motor criptográfico EC-SRP5 (Curve25519 / SHA-256) e fallback MD5 legado.
* [`crates/mkt-net`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-net): Abstração de TAP virtual, sockets UDP e transporte streaming HTTPS TCP 443.
* [`crates/mkt-core`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-core): Máquinas de estado de sessão, gerência de túneis e tabela de roteamento.
* [`crates/mkt-php`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-php): Biblioteca compartilhada C-ABI (`libmkt_php.so` / `mkt_php.dll`).
* [`crates/mkt-cli`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/crates/mkt-cli): Binário CLI unificado para terminal, túneis e auditoria.
* [`php/`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/php): Classes PHP (`MikrotikVpnManager.php`) e gateway HTTP 443 (`gateway.php`).
---

## 📦 Diagramas dos Pacotes (ASCII Frame Layouts)

### 1. Pacote EoIP / GRE MikroTik (RFC 1701 + EtherType 0x6400)
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

### 2. Pacote MAC-Telnet MikroTik (22 Bytes de Cabeçalho)
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

### 3. Enquadramento de Streaming Multiplexado sobre HTTPS TCP 443
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

---

## 🚀 Como Compilar e Testar

### Compilando o Workspace
```bash
cargo build --release
```

### Executando os Testes Automatizados
```bash
cargo test
```

### Executando a Bateria de Cibersegurança
```bash
cargo run -p mkt-cli -- security-audit
```

---

## 📖 Comandos do CLI (`mkt-cli`)

### 1. MAC-Telnet (Conectar a um MikroTik)
```bash
# Conectar no RouterOS via endereço MAC:
mkt-cli mactelnet connect 00:0C:42:1F:2A:3B -u admin -p MinhaSenha123

# Escanear vizinhos MikroTik via MNDP:
mkt-cli mactelnet scan --timeout 5

# Subir servidor de terminal Linux acessível via MAC-Telnet:
mkt-cli mactelnet server --mac 00:11:22:33:44:55 -u admin -p Segredo
```

### 2. EoIP (Túnel L2 & Relay TCP 443)
```bash
# Subir túnel EoIP conectado diretamente a um MikroTik (GRE puro nativo, Protocolo IP 47):
mkt-cli eoip tunnel --tunnel-id 100 --remote 192.168.88.1 --tap eoip0

# Subir túnel EoIP encapsulado sobre HTTPS TCP 443 (para atravessar CGNAT/VPS):
mkt-cli eoip tunnel --tunnel-id 100 --remote vps.minhadominio.com:443 --tap eoip0 --relay-443

# Subir o servidor de Relay Central na VPS (porta 443):
mkt-cli eoip relay --bind 0.0.0.0:443
```

---

## 🛰️ STUN Gateway & Descoberta Peer-to-Peer Nativa no CLI

Para nós em redes com NAT ou CGNAT, a suíte conta com descoberta STUN totalmente integrada ao executável `mkt-cli` (sem necessidade de comandos `curl` manuais):

* **Endpoint Padrão (Oficial):** `https://carloslopes.programandosolucoes.com.br/mesh/gateway.php`
* **Suporte a Servidor STUN Próprio:** Qualquer usuário ou empresa pode hospedar seu próprio `gateway.php` (em Apache, Nginx, XAMPP ou VPS) e apontar o `mkt-cli` para sua própria URL via `--stun-url` (ou `--url`) e `--stun-token` (ou `--token`).

### 1. Subir o Túnel EoIP com Descoberta Automática STUN:
Basta passar a flag `--stun`, o seu ID de nó (`--peer-id`) e o nó com quem deseja falar (`--target-peer`):

```bash
# Usando o STUN padrão oficial:
# Na Ponta A (Casa):
mkt-cli eoip tunnel --tunnel-id 500 --stun --peer-id ponta_a --target-peer ponta_b --tap eoip0

# Na Ponta B (Filial):
mkt-cli eoip tunnel --tunnel-id 500 --stun --peer-id ponta_b --target-peer ponta_a --tap eoip0
```

#### Usando um Servidor STUN Próprio / Customizado:
Se você hospedar seu próprio gateway STUN:
```bash
# Na Ponta A:
mkt-cli eoip tunnel --tunnel-id 500 --stun \
  --stun-url "https://meu-servidor.com/meu_gateway.php" \
  --stun-token "meu_token_secreto_2026" \
  --peer-id ponta_a --target-peer ponta_b --tap eoip0

# Na Ponta B:
mkt-cli eoip tunnel --tunnel-id 500 --stun \
  --stun-url "https://meu-servidor.com/meu_gateway.php" \
  --stun-token "meu_token_secreto_2026" \
  --peer-id ponta_b --target-peer ponta_a --tap eoip0
```
*O binário se encarrega de contatar o STUN Gateway automaticamente, publicar as coordenadas, aguardar a outra ponta, resolver os IPs públicos/locais e estabelecer o túnel EoIP diretamente.*

### 2. Comandos de Diagnóstico STUN no Executável:
```bash
# Verificar status do Gateway STUN oficial:
mkt-cli eoip stun status

# Verificar status de um Gateway STUN próprio:
mkt-cli eoip stun status --url "https://meu-servidor.com/gateway.php" --token "meu_token"

# Registrar e consultar candidatos manualmente pelo binário:
mkt-cli eoip stun exchange --url "https://meu-servidor.com/gateway.php" --tunnel-id 500 --peer-id ponta_a --target-peer ponta_b
```


---

## 🧪 Bateria Completa de Testes de Integração (`tests/`)

Todos os testes de ponta a ponta estão consolidados na pasta [`tests/`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/tests):
1. **`tests/e2e_ping_traffic.rs`**:
   - Tráfego bidirecional sobre Relay Hub em plaintext e com criptografia ChaCha20-Poly1305 AEAD.
   - Burst de 10 pings ICMP com medição de RTT (min/avg/max) e 0% de perda.
   - Filtragem e bloqueio ativo de MACs não autorizados.
2. **`tests/legacy_and_stun_integration.rs`**:
   - Coordenação STUN real entre múltiplos nós Linux via HTTP/HTTPS JSON.
   - Autenticação e compatibilidade com **MikroTik RouterOS versões anteriores (v4, v5 e v6 < 6.43)** usando desafio MD5 clássico (`md5(0x00 + password + challenge)`).
   - Sessões interativas MAC-Telnet em modo texto/plaintext das versões anteriores.

Para executar todos os testes da suíte:
```bash
cargo test
```

---

## 🌐 Integração com PHP e XAMPP

Para usar em qualquer servidor PHP com XAMPP ou Hostinger:
1. Copie o binário compilado (`target/release/libmkt_php.so` ou `mkt_php.dll`) para a pasta do projeto PHP.
2. Certifique-se de que a extensão `ffi` está ativada no `php.ini` (`extension=ffi`).
3. Instancie o gerenciador no seu código PHP:

```php
require_once __DIR__ . '/php/MikrotikVpnManager.php';

$vpn = new MikrotikVpnManager();
$vpn->addRoute(100, "MikroTik-Matriz", "187.x.x.x:443", true);

$routes = $vpn->listRoutes();
print_r($routes);
```

