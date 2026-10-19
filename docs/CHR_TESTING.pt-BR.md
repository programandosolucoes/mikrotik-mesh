# Guia de Laboratório e Testes com MikroTik CHR (RouterOS v7)

Este guia orienta como subir uma máquina virtual com o **MikroTik RouterOS v7 CHR (Cloud Hosted Router)** para validar em laboratório o **MAC-Telnet** (cliente e servidor) e os túneis **EoIP**.

---

## 1. Obtendo o RouterOS v7 CHR Gratuitamente

A MikroTik disponibiliza imagens de disco gratuitas do CHR. O modo "Free" limita a velocidade de cada interface a 1 Mbps, o que é perfeito para validar sessões de terminal e túneis L2.

```bash
# Baixar a imagem raw da última versão do RouterOS v7:
wget https://download.mikrotik.com/routeros/7.16/chr-7.16.img.zip
unzip chr-7.16.img.zip
```

---

## 2. Criando o Segmento de Rede L2 Isolado com QEMU e TAP

Para que o RouterOS na VM e sua máquina Linux/Windows conversem na mesma Camada 2:

```bash
# 1. Cria a interface virtual TAP no host Linux:
sudo ip tuntap add mode tap dev tap-mkt
sudo ip link set tap-mkt up

# 2. Inicia o MikroTik CHR via QEMU conectado à interface TAP:
qemu-system-x86_64 -m 256M -smp 1 \
  -drive file=chr-7.16.img,format=raw \
  -netdev tap,id=net0,ifname=tap-mkt,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0,mac=00:0c:42:01:02:03 \
  -nographic
```

O RouterOS iniciará no terminal. Faça login com usuário `admin` e senha em branco.

---

## 3. Teste 1: Cliente Rust MAC-Telnet -> Servidor MikroTik

No seu host:
```bash
# Executa a descoberta de vizinhos via MNDP:
mkt-cli mactelnet scan --timeout 3
# Resultado esperado: O CHR será descoberto com MAC 00:0C:42:01:02:03

# Conectar via MAC-Telnet no CHR:
mkt-cli mactelnet connect 00:0C:42:01:02:03 -u admin
```
O cliente negociará o handshake criptográfico **EC-SRP5** automaticamente com o RouterOS v7 e abrirá a sessão do terminal.

---

## 4. Teste 2: Cliente MikroTik -> Servidor Rust MAC-Telnet

1. No seu host, inicie o daemon servidor em Rust:
   ```bash
   mkt-cli mactelnet server --mac 00:11:22:33:44:55 --user carlos --pass segredo123
   ```
2. No console do MikroTik CHR, digite:
   ```text
   /tool mac-telnet 00:11:22:33:44:55
   ```
3. O RouterOS solicitará usuário e senha (`carlos` / `segredo123`), executará o handshake EC-SRP5 contra o seu servidor Rust e abrirá a sessão.

---

## 5. Teste 3: Túnel EoIP entre Host e MikroTik

1. No MikroTik CHR, configure a interface EoIP:
   ```text
   /ip address add address=192.168.100.2/24 interface=ether1
   /interface eoip add name=eoip-lab tunnel-id=200 remote-address=192.168.100.1
   /ip address add address=10.0.0.1/24 interface=eoip-lab
   ```

2. No Host, suba o túnel EoIP com o mesmo `tunnel-id=200`:
   ```bash
   sudo ip addr add 192.168.100.1/24 dev tap-mkt
   mkt-cli eoip tunnel --tunnel-id 200 --remote 192.168.100.2 --tap eoip0
   ```

3. Em outro terminal do Host:
   ```bash
   sudo ip addr add 10.0.0.2/24 dev eoip0
   sudo ip link set eoip0 up
   ping 10.0.0.1
   ```
**Resultado Esperado:** O ping responderá com sucesso passando por dentro do túnel EoIP em userspace!
