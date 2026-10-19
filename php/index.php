<?php
/**
 * index.php
 * 
 * MikroTik Mesh VPN & Wakeup Hub Web Management Panel
 * Lightweight, decoupled web interface communicating with the Rust engine via FFI or Control API.
 * Default language: English (with one-click Portuguese translation toggle).
 */

session_start();

// Language selection (Default: English)
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'pt'])) {
    $_SESSION['lang'] = $_GET['lang'];
}
$lang = $_SESSION['lang'] ?? 'en';

$t = [
    'en' => [
        'title' => 'MikroTik Mesh VPN & Wakeup Hub',
        'login_title' => 'MikroTik Mesh Login',
        'username' => 'Username',
        'password' => 'Password',
        'login_button' => 'Sign In',
        'invalid_credentials' => 'Invalid username or password!',
        'logout' => 'Sign Out',
        'engine_version' => 'Rust Engine',
        'start_service' => '▶ Start Service (nohup)',
        'stop_service' => '⏹ Stop Service',
        'stop_confirm' => 'Are you sure you want to stop the background service?',
        'active_tunnels' => 'Active EoIP Tunnels & MAC Filters',
        'no_tunnels' => 'No active tunnels configured. Add a tunnel below.',
        'th_tunnel_id' => 'Tunnel ID',
        'th_peer_name' => 'Peer Name',
        'th_remote_endpoint' => 'Remote Endpoint',
        'th_mac_filter' => 'Allowed MAC Filter',
        'th_actions' => 'Actions',
        'disconnect' => 'Disconnect',
        'disconnect_confirm' => 'Disconnect and remove this tunnel?',
        'all_macs' => 'All (No Filter)',
        'waiting_tcp' => 'Waiting for TCP 443 relay',
        'add_tunnel_title' => 'Register / Edit EoIP Tunnel',
        'label_tunnel_id' => 'Tunnel ID:',
        'label_peer_name' => 'Peer / Device Name:',
        'label_endpoint' => 'Remote Endpoint (Optional):',
        'label_allowed_macs' => 'Allowed MACs (Comma-separated):',
        'save_tunnel' => 'Save Tunnel',
        'stun_tokens_title' => '🔑 STUN Access Tokens & CLI Parity',
        'stun_tokens_desc' => 'Dynamic access tokens issued by the server with tunnel-level isolation and timing-attack protection. The `mkt-cli` client must provide an active token issued here to authenticate NAT peer discovery.',
        'issue_token_title' => '➕ Issue New Access Token',
        'authorized_tunnel' => 'Authorized Tunnel:',
        'global_tunnel' => 'Global (Valid for any tunnel)',
        'token_label' => 'Client Label / Description:',
        'token_label_ph' => 'e.g. Branch Office SP or Home',
        'generate_button' => 'Generate Access Token',
        'no_tokens' => 'No tokens issued yet. Generate an access token above to allow `mkt-cli` connections.',
        'th_label' => 'Label / Description',
        'th_tunnel' => 'Tunnel',
        'th_token' => 'Authentication Token',
        'th_created' => 'Created At',
        'th_status' => 'Status',
        'status_active' => '● Active',
        'status_revoked' => '○ Revoked',
        'revoke' => 'Revoke',
        'reactivate' => 'Reactivate',
        'delete' => 'Delete',
        'delete_confirm' => 'Permanently delete this token?',
        'wakeup_title' => '⚡ Fast Wakeup Actions (Remote Device Wake)',
        'ps5_title' => '🎮 Wake PlayStation 5 (UDP 9302)',
        'discover_network' => '🔍 Discover on Network',
        'ps5_ip_label' => 'PS5 IP Address on Local Network / VPN:',
        'ps5_cred_label' => 'PSN User Credential (Required for PS5 in Rest Mode):',
        'ps5_cred_help' => 'Captured from the official PS Remote Play app (UDP packet on port 9302 containing `user-credential:`) or Base64 of your PSN Account-ID.',
        'ps5_wake_button' => '⚡ Wake PS5',
        'wol_title' => '💻 Standard Wake-on-LAN (WoL)',
        'wol_mac_label' => 'Computer / Console MAC Address:',
        'wol_bcast_label' => 'Broadcast Address:',
        'wol_button' => '⚡ Send Magic Packet',
        'tunnel_added' => 'Tunnel #%d (%s) configured successfully!',
        'tunnel_removed' => 'Tunnel #%d removed successfully!',
        'token_generated' => 'New STUN access token generated successfully: <code>%s</code>',
        'token_revoked' => 'STUN token revoked successfully.',
        'token_activated' => 'STUN token reactivated successfully.',
        'token_deleted' => 'STUN token deleted successfully.',
        'service_started' => 'Background service started via nohup / start command!',
        'service_stopped' => 'Background service stopped.',
        'ps5_sent' => 'PS5 Wakeup packet (UDP 9302) transmitted to %s!',
        'ps5_fail' => 'Failed to send PS5 wakeup packet.',
        'ps5_found' => 'PlayStation 5 located on local network: %s',
        'ps5_not_found' => 'No PlayStation 5 responded to broadcast probe (UDP 9302).',
        'wol_sent' => 'Wake-on-LAN Magic Packet sent to %s via %s',
    ],
    'pt' => [
        'title' => 'MikroTik Mesh VPN & Central de Wakeup',
        'login_title' => 'Login MikroTik Mesh',
        'username' => 'Usuário',
        'password' => 'Senha',
        'login_button' => 'Entrar no Painel',
        'invalid_credentials' => 'Usuário ou senha incorretos!',
        'logout' => 'Sair',
        'engine_version' => 'Motor Rust',
        'start_service' => '▶ Iniciar Serviço (nohup)',
        'stop_service' => '⏹ Parar Serviço',
        'stop_confirm' => 'Deseja realmente parar o serviço em segundo plano?',
        'active_tunnels' => 'Túneis EoIP Ativos & Filtros de MAC',
        'no_tunnels' => 'Nenhum túnel ativo no momento. Cadastre um túnel abaixo.',
        'th_tunnel_id' => 'ID do Túnel',
        'th_peer_name' => 'Nome do Peer',
        'th_remote_endpoint' => 'Endpoint Remoto',
        'th_mac_filter' => 'Filtro de MAC Permitido',
        'th_actions' => 'Ações',
        'disconnect' => 'Desconectar',
        'disconnect_confirm' => 'Remover e desconectar este túnel?',
        'all_macs' => 'Todos (Sem filtro)',
        'waiting_tcp' => 'Aguardando relay TCP 443',
        'add_tunnel_title' => 'Cadastrar / Editar Túnel EoIP',
        'label_tunnel_id' => 'ID do Túnel:',
        'label_peer_name' => 'Nome do Peer / Dispositivo:',
        'label_endpoint' => 'Endpoint Remoto (Opcional):',
        'label_allowed_macs' => 'MACs Permitidos (Separados por vírgula):',
        'save_tunnel' => 'Salvar Túnel',
        'stun_tokens_title' => '🔑 Tokens de Acesso STUN & Paridade CLI',
        'stun_tokens_desc' => 'Tokens dinâmicos emitidos pelo servidor com isolamento de túnel e proteção contra timing attacks. O cliente `mkt-cli` deve utilizar um token ativo emitido aqui para autenticar a descoberta de peers no STUN Gateway.',
        'issue_token_title' => '➕ Emitir Novo Token de Acesso',
        'authorized_tunnel' => 'Túnel Autorizado:',
        'global_tunnel' => 'Global (Válido para qualquer túnel)',
        'token_label' => 'Rótulo / Descrição do Cliente:',
        'token_label_ph' => 'Ex: Filial Rio de Janeiro ou Casa',
        'generate_button' => 'Gerar Chave de Acesso',
        'no_tokens' => 'Nenhum token emitido até o momento. Gere uma chave acima para permitir conexões do `mkt-cli`.',
        'th_label' => 'Rótulo / Descrição',
        'th_tunnel' => 'Túnel',
        'th_token' => 'Token de Autenticação',
        'th_created' => 'Criado em',
        'th_status' => 'Status',
        'status_active' => '● Ativo',
        'status_revoked' => '○ Revogado',
        'revoke' => 'Revogar',
        'reactivate' => 'Reativar',
        'delete' => 'Excluir',
        'delete_confirm' => 'Excluir este token permanentemente?',
        'wakeup_title' => '⚡ Ações Rápidas de Wakeup (Acordar Dispositivos)',
        'ps5_title' => '🎮 Acordar PlayStation 5 (UDP 9302)',
        'discover_network' => '🔍 Buscar na Rede',
        'ps5_ip_label' => 'IP do PS5 na Rede Local / VPN:',
        'ps5_cred_label' => 'Credencial de Usuário PSN (Obrigatório em Modo Repouso):',
        'ps5_cred_help' => 'Capturado do app oficial PS Remote Play (pacote UDP na porta 9302 contendo `user-credential:`) ou Base64 do seu PSN Account-ID.',
        'ps5_wake_button' => '⚡ Acordar PS5',
        'wol_title' => '💻 Wake-on-LAN Padrão (WoL)',
        'wol_mac_label' => 'Endereço MAC do Computador/Console:',
        'wol_bcast_label' => 'Endereço de Broadcast:',
        'wol_button' => '⚡ Enviar Magic Packet',
        'tunnel_added' => 'Túnel #%d (%s) configurado com sucesso!',
        'tunnel_removed' => 'Túnel #%d removido com sucesso!',
        'token_generated' => 'Novo token STUN gerado com sucesso: <code>%s</code>',
        'token_revoked' => 'Token STUN revogado com sucesso.',
        'token_activated' => 'Token STUN reativado.',
        'token_deleted' => 'Token STUN excluído com sucesso.',
        'service_started' => 'Serviço em segundo plano iniciado via comando nohup / start!',
        'service_stopped' => 'Serviço em segundo plano interrompido.',
        'ps5_sent' => 'Pacote de Wakeup PS5 (UDP 9302) enviado para %s!',
        'ps5_fail' => 'Falha ao enviar pacote de wakeup do PS5.',
        'ps5_found' => 'PlayStation 5 localizado na rede: %s',
        'ps5_not_found' => 'Nenhum PlayStation 5 respondeu ao probe de broadcast (UDP 9302).',
        'wol_sent' => 'Magic Packet Wake-on-LAN enviado para %s via %s',
    ]
];

$msg = $t[$lang];

// Logout
if (isset($_GET['logout'])) {
    unset($_SESSION['mkt_auth']);
    session_destroy();
    header('Location: index.php');
    exit;
}

// Login verification
if (isset($_POST['login_action'])) {
    $user = trim($_POST['user'] ?? '');
    $pass = trim($_POST['pass'] ?? '');
    if ($user === 'admin' && $pass === 'admin') {
        $_SESSION['mkt_auth'] = true;
        header('Location: index.php');
        exit;
    } else {
        $loginError = $msg['invalid_credentials'];
    }
}

if (empty($_SESSION['mkt_auth'])) {
    ?>
    <!DOCTYPE html>
    <html lang="<?= $lang ?>">
    <head>
        <meta charset="UTF-8">
        <title><?= htmlspecialchars($msg['login_title']) ?></title>
        <style>
            body { background: #0f172a; color: #f8fafc; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .login-card { background: #1e293b; padding: 30px; border-radius: 8px; border: 1px solid #334155; width: 320px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
            h2 { margin-top: 0; font-size: 1.2rem; color: #38bdf8; text-align: center; }
            label { display: block; margin: 12px 0 4px; font-size: 0.85rem; color: #94a3b8; }
            input { width: 100%; box-sizing: border-box; padding: 10px; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #fff; }
            button { width: 100%; margin-top: 20px; padding: 10px; background: #38bdf8; color: #0f172a; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
            .err { color: #f87171; font-size: 0.85rem; text-align: center; margin-top: 10px; }
            .lang-switch { text-align: center; margin-bottom: 15px; font-size: 0.8rem; }
            .lang-switch a { color: #38bdf8; text-decoration: none; margin: 0 5px; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="lang-switch">
                <a href="?lang=en" style="<?= $lang === 'en' ? 'font-weight:bold;text-decoration:underline;' : '' ?>">English</a> |
                <a href="?lang=pt" style="<?= $lang === 'pt' ? 'font-weight:bold;text-decoration:underline;' : '' ?>">Português</a>
            </div>
            <h2>🌐 <?= htmlspecialchars($msg['login_title']) ?></h2>
            <?php if (!empty($loginError)): ?>
                <div class="err"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="hidden" name="login_action" value="1">
                <label><?= htmlspecialchars($msg['username']) ?>:</label>
                <input type="text" name="user" required autofocus>
                <label><?= htmlspecialchars($msg['password']) ?>:</label>
                <input type="password" name="pass" required>
                <button type="submit"><?= htmlspecialchars($msg['login_button']) ?></button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

require_once __DIR__ . '/TokenStore.php';
require_once __DIR__ . '/MikrotikVpnManager.php';

$message = null;
$messageType = "info";

try {
    $manager = new MikrotikVpnManager();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';

        if ($action === 'add_tunnel') {
            $tunnelId = (int)$_POST['tunnel_id'];
            $peerName = trim($_POST['peer_name']);
            $endpoint = trim($_POST['endpoint']);
            $allowedMacs = trim($_POST['allowed_macs']);

            $manager->addRoute($tunnelId, $peerName, $endpoint ?: null, true);
            if (!empty($allowedMacs)) {
                $manager->setMacFilter($tunnelId, $allowedMacs);
            }
            $message = sprintf($msg['tunnel_added'], $tunnelId, $peerName);
            $messageType = "success";
        } elseif ($action === 'remove_tunnel') {
            $tunnelId = (int)$_POST['tunnel_id'];
            $manager->removeRoute($tunnelId);
            $message = sprintf($msg['tunnel_removed'], $tunnelId);
            $messageType = "warning";
        } elseif ($action === 'generate_stun_token') {
            $tunnelId = (int)($_POST['token_tunnel_id'] ?? 0);
            $label = trim($_POST['token_label'] ?? '');
            $newToken = TokenStore::generateToken($tunnelId, $label);
            $message = sprintf($msg['token_generated'], $newToken);
            $messageType = "success";
        } elseif ($action === 'revoke_stun_token') {
            $token = trim($_POST['token'] ?? '');
            TokenStore::revokeToken($token);
            $message = $msg['token_revoked'];
            $messageType = "warning";
        } elseif ($action === 'activate_stun_token') {
            $token = trim($_POST['token'] ?? '');
            TokenStore::activateToken($token);
            $message = $msg['token_activated'];
            $messageType = "success";
        } elseif ($action === 'delete_stun_token') {
            $token = trim($_POST['token'] ?? '');
            TokenStore::deleteToken($token);
            $message = $msg['token_deleted'];
            $messageType = "danger";
        } elseif ($action === 'send_ps5_wake') {
            $ip = trim($_POST['ps5_ip']);
            $cred = trim($_POST['ps5_cred']);
            $ok = $manager->sendPs5Wakeup($ip, $cred ?: null);
            $message = $ok ? sprintf($msg['ps5_sent'], $ip) : $msg['ps5_fail'];
            $messageType = $ok ? "success" : "danger";
        } elseif ($action === 'discover_ps5') {
            $found = $manager->discoverPs5();
            if (!empty($found)) {
                $ips = array_map(function($d) { return "{$d['host_name']} ({$d['ip']})"; }, $found);
                $message = sprintf($msg['ps5_found'], implode(', ', $ips));
                $messageType = "success";
                $discoveredIp = $found[0]['ip'] ?? '';
            } else {
                $message = $msg['ps5_not_found'];
                $messageType = "warning";
            }
        } elseif ($action === 'send_wol') {
            $mac = trim($_POST['wol_mac']);
            $bcast = trim($_POST['wol_bcast'] ?? '255.255.255.255:9');
            $ok = $manager->sendWol($mac, $bcast);
            $message = $ok ? sprintf($msg['wol_sent'], $mac, $bcast) : "Failed to send WOL magic packet.";
            $messageType = $ok ? "success" : "danger";
        } elseif ($action === 'start_service') {
            $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            $pidFile = sys_get_temp_dir() . '/mkt_mesh_daemon.pid';
            $logFile = sys_get_temp_dir() . '/mkt_mesh_daemon.log';

            if ($isWindows) {
                $binPath = realpath(__DIR__ . '/../target/release/mkt-cli.exe') ?: 'mkt-cli.exe';
                pclose(popen("start /B \"\" \"$binPath\" daemon --control 127.0.0.1:20560 --relay 0.0.0.0:443 > \"$logFile\" 2>&1", "r"));
            } else {
                $binPath = realpath(__DIR__ . '/../target/release/mkt-cli') ?: '/usr/local/bin/mkt-cli';
                exec("nohup $binPath daemon --control 127.0.0.1:20560 --relay 0.0.0.0:443 > '$logFile' 2>&1 & echo $! > '$pidFile'");
            }
            sleep(1);
            $message = $msg['service_started'];
            $messageType = "success";
        } elseif ($action === 'stop_service') {
            $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            $pidFile = sys_get_temp_dir() . '/mkt_mesh_daemon.pid';
            if ($isWindows) {
                exec("taskkill /F /IM mkt-cli.exe 2>&1");
            } else {
                if (file_exists($pidFile)) {
                    $pid = (int)trim(file_get_contents($pidFile));
                    if ($pid > 0) {
                        posix_kill($pid, SIGTERM);
                        @unlink($pidFile);
                    }
                }
                exec("pkill -f 'mkt-cli daemon' 2>&1");
            }
            $message = $msg['service_stopped'];
            $messageType = "warning";
        }
    }

    $routes = $manager->listRoutes();
    $stunTokens = TokenStore::listTokens();
    $version = MikrotikVpnManager::getVersion();
} catch (\Throwable $e) {
    $message = "Engine communication error: " . $e->getMessage();
    $messageType = "danger";
    $routes = [];
    $stunTokens = [];
    $version = 0;
}
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($msg['title']) ?></title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --primary: #3b82f6;
            --accent: #10b981;
            --danger: #ef4444;
            --text: #f8fafc;
            --text-muted: #94a3b8;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        h1 { margin: 0; font-size: 1.4rem; display: flex; align-items: center; gap: 10px; }
        .badge {
            background: #0284c7;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.8rem;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }
        h2 { font-size: 1.1rem; margin-top: 0; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 10px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        th { color: var(--text-muted); }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 5px; }
        input, select {
            width: 100%;
            padding: 8px 12px;
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            box-sizing: border-box;
        }
        button {
            padding: 9px 18px;
            background: var(--primary);
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.9; }
        button.btn-danger { background: var(--danger); padding: 5px 10px; font-size: 0.8rem; }
        button.btn-accent { background: var(--accent); }
        .alert {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }
        .alert-success { background: #064e3b; color: #a7f3d0; border: 1px solid #059669; }
        .alert-warning { background: #78350f; color: #fde68a; border: 1px solid #d97706; }
        .alert-danger { background: #7f1d1d; color: #fecaca; border: 1px solid #dc2626; }
        .tag-mac {
            display: inline-block;
            background: #334155;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            margin: 2px;
        }
        .lang-link {
            color: #94a3b8;
            text-decoration: none;
            padding: 4px 8px;
            border: 1px solid var(--border);
            border-radius: 4px;
            font-size: 0.8rem;
        }
        .lang-link.active {
            color: #38bdf8;
            font-weight: bold;
            border-color: #38bdf8;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>🌐 <?= htmlspecialchars($msg['title']) ?></h1>
        <div style="display: flex; gap: 8px; align-items: center;">
            <div style="display: flex; gap: 4px; margin-right: 8px;">
                <a href="?lang=en" class="lang-link <?= $lang === 'en' ? 'active' : '' ?>">EN</a>
                <a href="?lang=pt" class="lang-link <?= $lang === 'pt' ? 'active' : '' ?>">PT</a>
            </div>
            <form method="POST" style="display:inline; margin:0;">
                <input type="hidden" name="action" value="start_service">
                <button type="submit" style="background: #10b981; padding: 6px 12px; font-size: 0.8rem;"><?= htmlspecialchars($msg['start_service']) ?></button>
            </form>
            <form method="POST" style="display:inline; margin:0;">
                <input type="hidden" name="action" value="stop_service">
                <button type="submit" class="btn-danger" style="padding: 6px 12px; font-size: 0.8rem;" onclick="return confirm('<?= htmlspecialchars($msg['stop_confirm']) ?>')"><?= htmlspecialchars($msg['stop_service']) ?></button>
            </form>
            <span class="badge"><?= htmlspecialchars($msg['engine_version']) ?> v<?= $version ?></span>
            <a href="index.php?logout=1" style="color: #94a3b8; font-size: 0.8rem; text-decoration: none; padding: 4px 8px; border: 1px solid #334155; border-radius: 4px;"><?= htmlspecialchars($msg['logout']) ?></a>
        </div>
    </header>

    <?php if ($message): ?>
        <div class="alert alert-<?= $messageType ?>"><?= $message ?></div>
    <?php endif; ?>

    <!-- Tunnels Table -->
    <div class="card">
        <h2><?= htmlspecialchars($msg['active_tunnels']) ?></h2>
        <?php if (empty($routes)): ?>
            <p style="color: var(--text-muted); font-size: 0.9rem;"><?= htmlspecialchars($msg['no_tunnels']) ?></p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th><?= htmlspecialchars($msg['th_tunnel_id']) ?></th>
                        <th><?= htmlspecialchars($msg['th_peer_name']) ?></th>
                        <th><?= htmlspecialchars($msg['th_remote_endpoint']) ?></th>
                        <th><?= htmlspecialchars($msg['th_mac_filter']) ?></th>
                        <th><?= htmlspecialchars($msg['th_actions']) ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($routes as $route): ?>
                        <tr>
                            <td><strong>#<?= $route['tunnel_id'] ?></strong></td>
                            <td><?= htmlspecialchars($route['peer_name']) ?></td>
                            <td><code><?= htmlspecialchars($route['endpoint'] ?? $msg['waiting_tcp']) ?></code></td>
                            <td>
                                <?php if (!empty($route['allowed_macs'])): ?>
                                    <?php foreach ($route['allowed_macs'] as $m): ?>
                                        <span class="tag-mac"><?= htmlspecialchars($m) ?></span>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <span style="color: var(--text-muted);"><?= htmlspecialchars($msg['all_macs']) ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="remove_tunnel">
                                    <input type="hidden" name="tunnel_id" value="<?= $route['tunnel_id'] ?>">
                                    <button type="submit" class="btn-danger" onclick="return confirm('<?= htmlspecialchars($msg['disconnect_confirm']) ?>')"><?= htmlspecialchars($msg['disconnect']) ?></button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Add Tunnel Form -->
    <div class="card">
        <h2><?= htmlspecialchars($msg['add_tunnel_title']) ?></h2>
        <form method="POST">
            <input type="hidden" name="action" value="add_tunnel">
            <div class="form-grid">
                <div>
                    <label><?= htmlspecialchars($msg['label_tunnel_id']) ?></label>
                    <input type="number" name="tunnel_id" placeholder="e.g. 100" required>
                </div>
                <div>
                    <label><?= htmlspecialchars($msg['label_peer_name']) ?></label>
                    <input type="text" name="peer_name" placeholder="e.g. Branch-Router" required>
                </div>
                <div>
                    <label><?= htmlspecialchars($msg['label_endpoint']) ?></label>
                    <input type="text" name="endpoint" placeholder="e.g. 192.168.1.50:443">
                </div>
                <div>
                    <label><?= htmlspecialchars($msg['label_allowed_macs']) ?></label>
                    <input type="text" name="allowed_macs" placeholder="e.g. 00:D9:D1:11:22:33">
                </div>
            </div>
            <button type="submit"><?= htmlspecialchars($msg['save_tunnel']) ?></button>
        </form>
    </div>

    <!-- STUN Access Tokens -->
    <div class="card">
        <h2><?= htmlspecialchars($msg['stun_tokens_title']) ?></h2>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: -8px; margin-bottom: 15px;">
            <?= htmlspecialchars($msg['stun_tokens_desc']) ?>
        </p>

        <!-- Generate Token Form -->
        <form method="POST" style="background: #0f172a; padding: 15px; border-radius: 6px; border: 1px solid var(--border); margin-bottom: 20px;">
            <input type="hidden" name="action" value="generate_stun_token">
            <h3 style="margin-top:0; font-size:0.95rem; color: #38bdf8;"><?= htmlspecialchars($msg['issue_token_title']) ?></h3>
            <div class="form-grid">
                <div>
                    <label><?= htmlspecialchars($msg['authorized_tunnel']) ?></label>
                    <select name="token_tunnel_id">
                        <option value="0"><?= htmlspecialchars($msg['global_tunnel']) ?></option>
                        <?php foreach ($routes as $r): ?>
                            <option value="<?= $r['tunnel_id'] ?>">#<?= $r['tunnel_id'] ?> (<?= htmlspecialchars($r['peer_name']) ?>)</option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label><?= htmlspecialchars($msg['token_label']) ?></label>
                    <input type="text" name="token_label" placeholder="<?= htmlspecialchars($msg['token_label_ph']) ?>" required>
                </div>
            </div>
            <button type="submit" style="background: #0284c7;"><?= htmlspecialchars($msg['generate_button']) ?></button>
        </form>

        <!-- Tokens Table -->
        <?php if (empty($stunTokens)): ?>
            <p style="color: var(--text-muted); font-size: 0.9rem;"><?= htmlspecialchars($msg['no_tokens']) ?></p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th><?= htmlspecialchars($msg['th_label']) ?></th>
                        <th><?= htmlspecialchars($msg['th_tunnel']) ?></th>
                        <th><?= htmlspecialchars($msg['th_token']) ?></th>
                        <th><?= htmlspecialchars($msg['th_created']) ?></th>
                        <th><?= htmlspecialchars($msg['th_status']) ?></th>
                        <th><?= htmlspecialchars($msg['th_actions']) ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($stunTokens as $tok): ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($tok['label']) ?></strong></td>
                            <td>
                                <?php if (!empty($tok['tunnel_id'])): ?>
                                    <span class="badge" style="background: #0369a1;">#<?= $tok['tunnel_id'] ?></span>
                                <?php else: ?>
                                    <span class="badge" style="background: #475569;">Global</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <code style="background: #0f172a; padding: 3px 6px; border-radius: 4px; border: 1px solid var(--border); color: #38bdf8; font-size: 0.85rem; user-select: all;">
                                    <?= htmlspecialchars($tok['token']) ?>
                                </code>
                            </td>
                            <td style="font-size: 0.8rem; color: var(--text-muted);"><?= htmlspecialchars($tok['created_at']) ?></td>
                            <td>
                                <?php if ($tok['active']): ?>
                                    <span style="color: #4ade80; font-weight: bold; font-size: 0.8rem;"><?= htmlspecialchars($msg['status_active']) ?></span>
                                <?php else: ?>
                                    <span style="color: #f87171; font-weight: bold; font-size: 0.8rem;"><?= htmlspecialchars($msg['status_revoked']) ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div style="display: flex; gap: 5px;">
                                    <?php if ($tok['active']): ?>
                                        <form method="POST" style="margin:0;">
                                            <input type="hidden" name="action" value="revoke_stun_token">
                                            <input type="hidden" name="token" value="<?= htmlspecialchars($tok['token']) ?>">
                                            <button type="submit" class="btn-danger" style="padding: 3px 8px; font-size: 0.75rem;"><?= htmlspecialchars($msg['revoke']) ?></button>
                                        </form>
                                    <?php else: ?>
                                        <form method="POST" style="margin:0;">
                                            <input type="hidden" name="action" value="activate_stun_token">
                                            <input type="hidden" name="token" value="<?= htmlspecialchars($tok['token']) ?>">
                                            <button type="submit" class="btn-accent" style="padding: 3px 8px; font-size: 0.75rem;"><?= htmlspecialchars($msg['reactivate']) ?></button>
                                        </form>
                                    <?php endif; ?>
                                    <form method="POST" style="margin:0;">
                                        <input type="hidden" name="action" value="delete_stun_token">
                                        <input type="hidden" name="token" value="<?= htmlspecialchars($tok['token']) ?>">
                                        <button type="submit" class="btn-danger" style="background: #7f1d1d; padding: 3px 8px; font-size: 0.75rem;" onclick="return confirm('<?= htmlspecialchars($msg['delete_confirm']) ?>')"><?= htmlspecialchars($msg['delete']) ?></button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Wakeup Actions Card -->
    <div class="card">
        <h2><?= htmlspecialchars($msg['wakeup_title']) ?></h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <!-- Wake PS5 -->
            <div style="background: #0f172a; padding: 15px; border-radius: 6px; border: 1px solid var(--border);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <h3 style="margin:0; font-size:0.95rem; color: #60a5fa;"><?= htmlspecialchars($msg['ps5_title']) ?></h3>
                    <form method="POST" style="margin:0;">
                        <input type="hidden" name="action" value="discover_ps5">
                        <button type="submit" style="background:#2563eb; padding:4px 8px; font-size:0.75rem;"><?= htmlspecialchars($msg['discover_network']) ?></button>
                    </form>
                </div>
                <form method="POST">
                    <input type="hidden" name="action" value="send_ps5_wake">
                    <div style="margin-bottom: 10px;">
                        <label><?= htmlspecialchars($msg['ps5_ip_label']) ?></label>
                        <input type="text" name="ps5_ip" value="<?= htmlspecialchars($discoveredIp ?? '') ?>" placeholder="e.g. 10.10.10.50" required>
                    </div>
                    <div style="margin-bottom: 15px;">
                        <label><?= htmlspecialchars($msg['ps5_cred_label']) ?></label>
                        <input type="text" name="ps5_cred" placeholder="e.g. -394857201 or Base64 Account-ID" required>
                        <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 4px;">
                            <?= htmlspecialchars($msg['ps5_cred_help']) ?>
                        </small>
                    </div>
                    <button type="submit" class="btn-accent"><?= htmlspecialchars($msg['ps5_wake_button']) ?></button>
                </form>
            </div>

            <!-- Wake-on-LAN -->
            <form method="POST" style="background: #0f172a; padding: 15px; border-radius: 6px; border: 1px solid var(--border);">
                <input type="hidden" name="action" value="send_wol">
                <h3 style="margin-top:0; font-size:0.95rem; color: #34d399;"><?= htmlspecialchars($msg['wol_title']) ?></h3>
                <div style="margin-bottom: 10px;">
                    <label><?= htmlspecialchars($msg['wol_mac_label']) ?></label>
                    <input type="text" name="wol_mac" placeholder="e.g. 00:11:22:33:44:55" required>
                </div>
                <div style="margin-bottom: 15px;">
                    <label><?= htmlspecialchars($msg['wol_bcast_label']) ?></label>
                    <input type="text" name="wol_bcast" value="255.255.255.255:9">
                </div>
                <button type="submit" class="btn-accent"><?= htmlspecialchars($msg['wol_button']) ?></button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
