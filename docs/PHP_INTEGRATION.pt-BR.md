# Guia de Integração com PHP, XAMPP e Painéis Web

Este documento explica como utilizar a biblioteca **`mkt-php`** (`libmkt_php.so` / `mkt_php.dll`) e a classe [`php/MikrotikVpnManager.php`](file:///C:/Users/carlo/.gemini/antigravity/scratch/mikrotik-mesh/php/MikrotikVpnManager.php) em projetos PHP modernos (PHP 8.1+).

---

## 1. Requisitos no PHP

1. PHP 8.1 ou superior (CLI ou FPM).
2. Extensão **`FFI`** habilitada no seu `php.ini`:
   ```ini
   extension=ffi
   ffi.enable=true
   ```

---

## 2. Compilação da Biblioteca Dinâmica

Para compilar a `.so` (no Linux) ou a `.dll` (no Windows):

```bash
cargo build --release -p mkt-php
```

Os arquivos resultantes estarão em:
* **Linux:** `target/release/libmkt_php.so`
* **Windows:** `target/release/mkt_php.dll`

---

## 3. Exemplo Prático de Uso no PHP

### Gerenciando Túneis EoIP e Rotas

```php
<?php
require_once __DIR__ . '/php/MikrotikVpnManager.php';

try {
    // Inicializa o gerenciador FFI apontando para a biblioteca compilada
    $manager = new MikrotikVpnManager();
    echo "Versão do Motor Rust: " . MikrotikVpnManager::getVersion() . PHP_EOL;

    // 1. Cadastra um túnel EoIP para um MikroTik remoto
    $tunnelId = 1500;
    $peerName = "Filial-SaoPaulo";
    $endpoint = "187.55.120.30:443"; // Conectado via HTTPS 443

    $ok = $manager->addRoute($tunnelId, $peerName, $endpoint, true);
    echo $ok ? "Túnel #$tunnelId cadastrado com sucesso!" : "Falha ao cadastrar túnel";
    echo PHP_EOL;

    // 2. Lista os túneis ativos e métricas
    $routes = $manager->listRoutes();
    foreach ($routes as $route) {
        echo sprintf(
            "Túnel ID: %d | Peer: %s | Endpoint: %s | Relay: %s\n",
            $route['tunnel_id'],
            $route['peer_name'],
            $route['endpoint'] ?? 'Aguardando',
            $route['is_relay_active'] ? 'Sim' : 'Não'
        );
    }

    // 3. Inicia o servidor de relay em background na porta 443
    // (Útil ao rodar scripts CLI ou daemons em PHP)
    $manager->startHttpsRelay("0.0.0.0:443");

} catch (\Throwable $e) {
    echo "Erro: " . $e->getMessage() . PHP_EOL;
}
```

---

## 4. Integração com Frameworks (Laravel, Symfony)

Você pode registrar o `MikrotikVpnManager` como um serviço singleton no container de injeção de dependência do seu framework:

### Exemplo em Laravel (`AppServiceProvider.php`):
```php
public function register()
{
    $this->app->singleton(MikrotikVpnManager::class, function ($app) {
        return new MikrotikVpnManager(config('services.mikrotik.lib_path'));
    });
}
```

E consumir em qualquer Controller da sua API:
```php
public function listTunnels(MikrotikVpnManager $vpn)
{
    return response()->json($vpn->listRoutes());
}
```
