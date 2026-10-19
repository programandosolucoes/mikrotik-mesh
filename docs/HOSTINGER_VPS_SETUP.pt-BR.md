# Guia de Implantação em VPS (Hostinger) e Ambientes Restritos (XAMPP)

Este guia explica como configurar a suíte **mikrotik-mesh** em uma VPS da **Hostinger** (KVM ou Hospedagem Compartilhada com XAMPP/Apache) para atuar como Hub Central de VPN e STUN.

---

## 1. O Cenário: Por que a Porta 443 (HTTPS TCP)?

Na maioria dos provedores de hospedagem compartilhada ou planos VPS com firewalls gerenciados:
* **Protocolo GRE (IP 47) direto:** Frequentemente não tem suporte a NAT em conexões residenciais ou é bloqueado em hospedagens básicas.
* **Portas UDP arbitrárias:** Podem ser restritas por políticas de segurança.
* **Porta 443 (HTTPS TCP):** Está **sempre aberta** e passa por qualquer firewall, proxy reverso (Nginx, Cloudflare) ou CGNAT de operadoras.

A suíte resolve isso encapsulando frames de Camada 2 (EoIP e MAC-Telnet) dentro de um túnel TCP/HTTPS na porta 443.

---

## 2. Passo a Passo de Instalação na VPS Hostinger (KVM)

### Passo 1: Transferir e Compilar o Projeto
Na sua VPS Linux (Ubuntu/Debian na Hostinger):
```bash
sudo apt update && sudo apt install -y build-essential git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

git clone https://github.com/carlos/mikrotik-mesh.git
cd mikrotik-mesh
cargo build --release
```

### Passo 2: Executar o Servidor de Relay na Porta 443
```bash
# Executa o relay central escutando na porta 443
sudo ./target/release/mkt-cli eoip relay --bind 0.0.0.0:443
```

---

## 3. Passo a Passo em Hospedagem Compartilhada / XAMPP com PHP

Se você estiver usando um servidor web padrão com PHP (Apache/XAMPP):

1. Copie o binário compilado:
   * No Linux: `target/release/libmkt_php.so` para a pasta do seu site (ou `/usr/local/lib/`).
   * No Windows: `target/release/mkt_php.dll` para a pasta do XAMPP `htdocs`.
2. Certifique-se de que a extensão `ffi` está ativada no seu `php.ini`:
   ```ini
   extension=ffi
   ffi.enable=true
   ```
3. Coloque os arquivos [`php/MikrotikVpnManager.php`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/php/MikrotikVpnManager.php) e [`php/gateway.php`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/php/gateway.php) no seu servidor web.

### Testando a API do Gateway via cURL
```bash
# Consultar status do gateway:
curl -H "X-MKT-Auth: mkt_secure_token_2026" https://seu-dominio.com/gateway.php?action=status

# Registrar uma ponta de túnel EoIP:
curl -X POST -H "Content-Type: application/json" \
     -H "X-MKT-Auth: mkt_secure_token_2026" \
     -d '{"tunnel_id": 100, "peer_name": "Mikrotik-Escritorio", "listening_port": 443}' \
     https://seu-dominio.com/gateway.php?action=register
```

---

## 4. Conectando a Ponta Remota (Cliente) ao Hub

No cliente (seja em outro Linux, Windows ou máquina na ponta do MikroTik):
```bash
# O cliente conecta na sua VPS Hostinger pela porta 443 e cria a interface virtual local eoip0
sudo mkt-cli eoip tunnel --tunnel-id 100 --remote vps.seusite.com:443 --tap eoip0 --relay-443

# Atribua um IP na interface virtual local:
sudo ip addr add 10.10.10.2/24 dev eoip0
sudo ip link set eoip0 up
```

A interface `eoip0` agora se comunica em Camada 2 diretamente com o outro lado do túnel como se estivessem conectados no mesmo cabo de rede!
