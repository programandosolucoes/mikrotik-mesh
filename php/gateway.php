<?php
/**
 * gateway.php
 * 
 * Drop-in HTTPS TCP 443 gateway endpoint for XAMPP / Apache / Nginx / Hostinger.
 * Handles STUN discovery, peer registration, and tunnel status over standard port 443.
 */

header('Content-Type: application/json');
if (!defined('MKT_ACCESS')) {
    define('MKT_ACCESS', true);
}
require_once __DIR__ . '/TokenStore.php';
require_once __DIR__ . '/MikrotikVpnManager.php';

// Authentication token for authorized peers (supports X-Mkt-Auth or query param ?token=)
$authHeader = $_SERVER['HTTP_X_MKT_AUTH'] ?? $_GET['token'] ?? '';
$action = $_GET['action'] ?? 'status';
$tunnelId = (int)($_GET['tunnel_id'] ?? 0);

// Validate token dynamically against TokenStore
$tokenData = TokenStore::validateToken($authHeader, $tunnelId);
if (!$tokenData) {
    http_response_code(401);
    echo json_encode([
        'error' => 'Unauthorized: Invalid, expired, or unauthorized STUN authentication token for this tunnel.',
        'code' => 401
    ]);
    exit;
}

try {
    $manager = new MikrotikVpnManager();

    switch ($action) {
        case 'register':
            // Registers an endpoint observed by the web server
            $input = json_decode(file_get_contents('php://input'), true);
            $tunnelId = (int)($input['tunnel_id'] ?? 0);
            $peerName = (string)($input['peer_name'] ?? 'Peer-' . $tunnelId);
            $observedIp = $_SERVER['REMOTE_ADDR'];
            $observedPort = (int)($input['listening_port'] ?? 443);

            $endpoint = "$observedIp:$observedPort";
            $success = $manager->addRoute($tunnelId, $peerName, $endpoint, true);

            echo json_encode([
                'success' => $success,
                'action' => 'registered',
                'tunnel_id' => $tunnelId,
                'observed_endpoint' => $endpoint,
                'relay_enabled' => true
            ]);
            break;

        case 'query_peer':
            // STUN endpoint query: discovers the public IP:port of the remote peer to attempt direct UDP P2P
            $tunnelId = (int)($_GET['tunnel_id'] ?? 0);
            $routes = $manager->listRoutes();
            $peerRoute = null;
            foreach ($routes as $r) {
                if (($r['tunnel_id'] ?? 0) === $tunnelId) {
                    $peerRoute = $r;
                    break;
                }
            }

            echo json_encode([
                'success' => $peerRoute !== null,
                'tunnel_id' => $tunnelId,
                'peer_route' => $peerRoute,
                'client_public_ip' => $_SERVER['REMOTE_ADDR']
            ]);
            break;

        case 'exchange':
            // Web polling mailbox for P2P NAT punch signaling:
            // Peer A posts its NAT candidates, Peer B fetches them via polling
            $tunnelId = (int)($_GET['tunnel_id'] ?? 0);
            $peerId = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['peer_id'] ?? 'default');
            $mailboxDir = sys_get_temp_dir() . '/mkt_mesh_stun';
            @mkdir($mailboxDir, 0770, true);
            $mailboxFile = "$mailboxDir/tunnel_{$tunnelId}_{$peerId}.json";

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $payload = file_get_contents('php://input');
                file_put_contents($mailboxFile, $payload);
                echo json_encode(['success' => true, 'status' => 'stored']);
            } else {
                // GET: fetch candidate from the OTHER peer
                $targetPeer = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['target_peer'] ?? '');
                $targetFile = "$mailboxDir/tunnel_{$tunnelId}_{$targetPeer}.json";
                if (file_exists($targetFile)) {
                    $data = json_decode(file_get_contents($targetFile), true);
                    echo json_encode(['success' => true, 'candidate' => $data]);
                } else {
                    echo json_encode(['success' => false, 'waiting' => true]);
                }
            }
            break;

        case 'list':
            $routes = $manager->listRoutes();
            echo json_encode(['success' => true, 'tunnels' => $routes]);
            break;

        case 'status':
        default:
            echo json_encode([
                'status' => 'online',
                'service' => 'MikroTik EoIP/MAC-Telnet Mesh STUN Gateway',
                'version' => MikrotikVpnManager::getVersion(),
                'client_ip' => $_SERVER['REMOTE_ADDR']
            ]);
            break;
    }
} catch (\Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
