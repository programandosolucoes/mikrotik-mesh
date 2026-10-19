<?php
/**
 * TokenStore.php
 * 
 * Secure access token manager for STUN Gateway and CLI parity.
 * Provides cryptographically strong tokens with tunnel isolation and timing-attack resistance.
 */

if (!defined('MKT_ACCESS')) {
    define('MKT_ACCESS', true);
}

class TokenStore {
    private static $dbFile = __DIR__ . '/tokens_db.php';

    /**
     * Loads the token database from protected PHP storage
     */
    private static function loadDb(): array {
        if (!file_exists(self::$dbFile)) {
            self::saveDb(['tokens' => []]);
            return ['tokens' => []];
        }

        $data = include self::$dbFile;
        if (!is_array($data) || !isset($data['tokens'])) {
            return ['tokens' => []];
        }
        return $data;
    }

    /**
     * Atomically saves the token database to disk
     */
    private static function saveDb(array $data): bool {
        $export = var_export($data, true);
        $content = "<?php\n// Protected against direct web access\nif (!defined('MKT_ACCESS')) { http_response_code(403); exit('Forbidden'); }\nreturn " . $export . ";\n";
        return (bool)file_put_contents(self::$dbFile, $content, LOCK_EX);
    }

    /**
     * Generates a cryptographically secure token optionally bound to a specific tunnel ID
     */
    public static function generateToken(int $tunnelId = 0, string $label = '', ?string $peerId = null): string {
        $data = self::loadDb();
        
        // High-entropy 128-bit random token
        $token = 'mkt_tok_' . bin2hex(random_bytes(16));

        $data['tokens'][$token] = [
            'token' => $token,
            'tunnel_id' => $tunnelId,
            'peer_id' => $peerId ? trim($peerId) : null,
            'label' => $label ? trim($label) : ($tunnelId > 0 ? "Tunnel #$tunnelId" : "Global Access"),
            'created_at' => date('Y-m-d H:i:s'),
            'active' => true,
        ];

        self::saveDb($data);
        return $token;
    }

    /**
     * Validates a token with constant-time comparison (hash_equals) and per-tunnel scope isolation
     */
    public static function validateToken(?string $providedToken, int $requestedTunnelId = 0): ?array {
        if (empty($providedToken)) {
            return null;
        }

        $data = self::loadDb();
        
        foreach ($data['tokens'] as $storedToken => $info) {
            if (hash_equals($storedToken, $providedToken)) {
                if (empty($info['active'])) {
                    return null;
                }

                // If token is scoped to a specific tunnel (> 0) and request targets a tunnel (> 0),
                // enforce strict tunnel matching for cross-tenant isolation
                $tokenTunnel = (int)($info['tunnel_id'] ?? 0);
                if ($tokenTunnel > 0 && $requestedTunnelId > 0 && $tokenTunnel !== $requestedTunnelId) {
                    return null;
                }

                return $info;
            }
        }

        return null;
    }

    /**
     * Returns list of all registered tokens
     */
    public static function listTokens(): array {
        $data = self::loadDb();
        return array_values($data['tokens']);
    }

    /**
     * Revokes (deactivates) a token
     */
    public static function revokeToken(string $token): bool {
        $data = self::loadDb();
        if (isset($data['tokens'][$token])) {
            $data['tokens'][$token]['active'] = false;
            return self::saveDb($data);
        }
        return false;
    }

    /**
     * Reactivates a previously revoked token
     */
    public static function activateToken(string $token): bool {
        $data = self::loadDb();
        if (isset($data['tokens'][$token])) {
            $data['tokens'][$token]['active'] = true;
            return self::saveDb($data);
        }
        return false;
    }

    /**
     * Permanently deletes a token
     */
    public static function deleteToken(string $token): bool {
        $data = self::loadDb();
        if (isset($data['tokens'][$token])) {
            unset($data['tokens'][$token]);
            return self::saveDb($data);
        }
        return false;
    }
}
