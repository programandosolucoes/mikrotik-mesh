<?php
/**
 * MikrotikVpnManager.php
 * 
 * PHP Control-Plane wrapper for the high-performance Rust mkt-php library.
 * Compatible with any standard PHP 8.1+ installation (CLI, FPM, Apache, XAMPP, Hostinger).
 */

class MikrotikVpnManager
{
    private static ?\FFI $ffi = null;
    private static bool $ffiAttempted = false;
    private $routerPtr = null;
    private string $daemonUrl;

    /**
     * Initializes either the FFI binding or falls back to the daemon Control API (127.0.0.1:20560)
     */
    public function __construct(?string $libraryPath = null, string $daemonUrl = "http://127.0.0.1:20560")
    {
        $this->daemonUrl = rtrim($daemonUrl, '/');

        if (!self::$ffiAttempted) {
            self::$ffiAttempted = true;
            if (class_exists('\\FFI')) {
                try {
                    $lib = $libraryPath ?? self::detectLibraryPath();
                    $cdef = self::getCdefDefinitions();
                    self::$ffi = \FFI::cdef($cdef, $lib);
                    self::$ffi->mkt_init();
                } catch (\Throwable $e) {
                    self::$ffi = null;
                }
            }
        }

        if (self::$ffi !== null) {
            $this->routerPtr = self::$ffi->mkt_router_create();
        }
    }

    public function isFfiActive(): bool
    {
        return self::$ffi !== null && $this->routerPtr !== null;
    }

    public function __destruct()
    {
        if ($this->routerPtr !== null && self::$ffi !== null) {
            self::$ffi->mkt_router_free($this->routerPtr);
            $this->routerPtr = null;
        }
    }

    public static function getVersion(): int
    {
        return self::$ffi ? self::$ffi->mkt_version() : 1;
    }

    /**
     * Registers a new EoIP tunnel or updates an existing route
     */
    public function addRoute(int $tunnelId, string $peerName, ?string $endpoint = null, bool $isRelay = true): bool
    {
        if ($this->isFfiActive()) {
            $res = self::$ffi->mkt_route_add(
                $this->routerPtr,
                $tunnelId,
                $peerName,
                $endpoint ?? "",
                $isRelay ? 1 : 0
            );
            return $res === 0;
        }

        $res = $this->callDaemonApi('/api/tunnels', 'POST', [
            'tunnel_id' => $tunnelId,
            'peer_name' => $peerName,
            'endpoint' => $endpoint ?? "",
            'is_relay' => $isRelay
        ]);
        return isset($res['status']) && $res['status'] === 'ok';
    }

    /**
     * Sets allowed MAC address filter on a specific tunnel (e.g. only transport PS5 MAC)
     *
     * @param int $tunnelId
     * @param array|string $macs Single MAC string, comma-separated string, or array of MACs
     */
    public function setMacFilter(int $tunnelId, $macs): bool
    {
        $csv = is_array($macs) ? implode(',', $macs) : (string)$macs;
        if ($this->isFfiActive()) {
            return self::$ffi->mkt_route_set_mac_filter($this->routerPtr, $tunnelId, $csv) === 0;
        }

        $macList = array_values(array_filter(array_map('trim', explode(',', $csv))));
        $res = $this->callDaemonApi('/api/filter', 'POST', [
            'tunnel_id' => $tunnelId,
            'allowed_macs' => $macList
        ]);
        return isset($res['status']) && $res['status'] === 'ok';
    }

    /**
     * Sends a standard Wake-on-LAN Magic Packet to wake up a computer or console
     */
    public function sendWol(string $targetMac, string $broadcastAddr = "255.255.255.255:9"): bool
    {
        if ($this->isFfiActive()) {
            return self::$ffi->mkt_send_wol($targetMac, $broadcastAddr) === 0;
        }

        $res = $this->callDaemonApi('/api/wol', 'POST', [
            'target_mac' => $targetMac,
            'broadcast' => $broadcastAddr
        ]);
        return isset($res['status']) && $res['status'] === 'ok';
    }

    /**
     * Sends a PlayStation 5 Remote Play Wakeup Packet over UDP port 9302
     */
    public function sendPs5Wakeup(string $targetIp, ?string $userCredential = null): bool
    {
        if ($this->isFfiActive()) {
            return self::$ffi->mkt_send_ps5_wakeup($targetIp, $userCredential ?? "") === 0;
        }

        $res = $this->callDaemonApi('/api/ps5-wake', 'POST', [
            'target_ip' => $targetIp,
            'credential' => $userCredential ?? ""
        ]);
        return isset($res['status']) && $res['status'] === 'ok';
    }

    /**
     * Discovers PS5 consoles on the local network
     */
    public function discoverPs5(): array
    {
        $res = $this->callDaemonApi('/api/wakeup/ps5/discover', 'GET');
        return is_array($res) ? $res : [];
    }

    /**
     * Removes an active tunnel from the routing table
     */
    public function removeRoute(int $tunnelId): bool
    {
        if ($this->isFfiActive()) {
            return self::$ffi->mkt_route_remove($this->routerPtr, $tunnelId) === 0;
        }

        $res = $this->callDaemonApi('/api/tunnels/' . $tunnelId, 'DELETE');
        return isset($res['status']) && $res['status'] === 'ok';
    }

    /**
     * Lists all registered tunnels, stats, and allowed MAC filters
     */
    public function listRoutes(): array
    {
        if ($this->isFfiActive()) {
            $cStr = self::$ffi->mkt_routes_list_json($this->routerPtr);
            if ($cStr === null) {
                return [];
            }

            $json = \FFI::string($cStr);
            self::$ffi->mkt_string_free($cStr);

            return json_decode($json, true) ?: [];
        }

        $res = $this->callDaemonApi('/api/tunnels', 'GET');
        return is_array($res) ? $res : [];
    }

    /**
     * Starts the central HTTPS TCP 443 relay server in background
     */
    public function startHttpsRelay(string $bindAddr = "0.0.0.0:443"): bool
    {
        if ($this->isFfiActive()) {
            return self::$ffi->mkt_start_https_relay($bindAddr) === 0;
        }
        return true;
    }

    private function callDaemonApi(string $path, string $method = 'GET', array $data = []): ?array
    {
        $url = $this->daemonUrl . $path;
        $opts = [
            'http' => [
                'method' => $method,
                'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                'timeout' => 3.0,
                'ignore_errors' => true
            ]
        ];

        if ($method === 'POST' || $method === 'PUT') {
            $opts['http']['content'] = json_encode($data);
        }

        $context = stream_context_create($opts);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            return null;
        }

        return json_decode($result, true);
    }

    private static function detectLibraryPath(): string
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $filename = $isWindows ? 'mkt_php.dll' : 'libmkt_php.so';

        $searchPaths = [
            __DIR__ . '/../target/release/' . $filename,
            __DIR__ . '/../target/debug/' . $filename,
            '/usr/local/lib/' . $filename,
            '/usr/lib/' . $filename,
            __DIR__ . '/' . $filename,
        ];

        foreach ($searchPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        throw new \RuntimeException("Could not locate compiled library ($filename). Run 'cargo build --release' first.");
    }

    private static function getCdefDefinitions(): string
    {
        return <<<CDEF
        int mkt_init(void);
        int mkt_version(void);
        void* mkt_router_create(void);
        void mkt_router_free(void* router);
        void mkt_string_free(char* ptr);
        int mkt_route_add(void* router, uint16_t tunnel_id, const char* peer_name, const char* endpoint, int is_relay);
        int mkt_route_set_mac_filter(void* router, uint16_t tunnel_id, const char* macs_csv);
        int mkt_route_remove(void* router, uint16_t tunnel_id);
        char* mkt_routes_list_json(void* router);
        int mkt_send_wol(const char* target_mac, const char* broadcast_addr);
        int mkt_send_ps5_wakeup(const char* target_ip, const char* user_credential);
        int mkt_start_https_relay(const char* bind_addr);
CDEF;
    }
}
