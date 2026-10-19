use libc::c_char;
use mkt_core::{send_ps5_wakeup_packet, send_wol_packet, VpnRouter};
use mkt_crypto::SrpServerSession;
use mkt_net::HttpsRelayServer;
use mkt_proto::MacAddr;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;

use tokio::runtime::Runtime;
use tracing::info;

use std::sync::OnceLock;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("Failed to initialize Tokio runtime for PHP module")
    })
}


/// Initialize the library
#[no_mangle]
pub extern "C" fn mkt_init() -> i32 {
    let _ = get_runtime();
    0
}

/// Returns library version
#[no_mangle]
pub extern "C" fn mkt_version() -> i32 {
    1
}

/// Allocates a new VpnRouter instance
#[no_mangle]
pub extern "C" fn mkt_router_create() -> *mut VpnRouter {
    let router = Box::new(VpnRouter::new());
    Box::into_raw(router)
}

/// Frees a VpnRouter instance
#[no_mangle]
pub extern "C" fn mkt_router_free(router: *mut VpnRouter) {
    if !router.is_null() {
        unsafe {
            drop(Box::from_raw(router));
        }
    }
}

/// Frees a C string allocated by Rust
#[no_mangle]
pub extern "C" fn mkt_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Register or update a route in the VPN Router
#[no_mangle]
pub extern "C" fn mkt_route_add(
    router: *mut VpnRouter,
    tunnel_id: u16,
    peer_name_cstr: *const c_char,
    endpoint_cstr: *const c_char,
    is_relay: i32,
) -> i32 {
    if router.is_null() || peer_name_cstr.is_null() {
        return -1;
    }

    let router = unsafe { &*router };
    let peer_name = match unsafe { CStr::from_ptr(peer_name_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let endpoint: Option<SocketAddr> = if !endpoint_cstr.is_null() {
        match unsafe { CStr::from_ptr(endpoint_cstr) }.to_str() {
            Ok(s) if !s.is_empty() => s.parse().ok(),
            _ => None,
        }
    } else {
        None
    };

    let rt = get_runtime();
    rt.block_on(async {
        router
            .register_or_update_route(tunnel_id, peer_name, endpoint, is_relay != 0)
            .await;
    });

    0
}

/// Set allowed MAC address filter for a specific tunnel (comma-separated list, e.g. "00:D9:D1:11:22:33,00:11:22:33:44:55")
#[no_mangle]
pub extern "C" fn mkt_route_set_mac_filter(
    router: *mut VpnRouter,
    tunnel_id: u16,
    macs_csv_cstr: *const c_char,
) -> i32 {
    if router.is_null() || macs_csv_cstr.is_null() {
        return -1;
    }

    let router = unsafe { &*router };
    let csv_str = match unsafe { CStr::from_ptr(macs_csv_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let macs: Vec<String> = csv_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let rt = get_runtime();
    match rt.block_on(async { router.set_mac_filter(tunnel_id, macs).await }) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

/// Remove a route from the VPN Router
#[no_mangle]
pub extern "C" fn mkt_route_remove(router: *mut VpnRouter, tunnel_id: u16) -> i32 {
    if router.is_null() {
        return -1;
    }

    let router = unsafe { &*router };
    let rt = get_runtime();
    match rt.block_on(async { router.remove_route(tunnel_id).await }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// List active routes in JSON format (including allowed_macs)
#[no_mangle]
pub extern "C" fn mkt_routes_list_json(router: *mut VpnRouter) -> *mut c_char {
    if router.is_null() {
        return std::ptr::null_mut();
    }

    let router = unsafe { &*router };
    let rt = get_runtime();
    let routes = rt.block_on(async { router.list_routes().await });

    let json_routes: Vec<serde_json::Value> = routes
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "tunnel_id": r.tunnel_id,
                "peer_name": r.peer_name,
                "endpoint": r.observed_endpoint.map(|e| e.to_string()),
                "is_relay_active": r.is_relay_active,
                "allowed_macs": r.allowed_macs,
                "tx_bytes": r.tx_bytes,
                "rx_bytes": r.rx_bytes,
            })
        })
        .collect();

    let json_str = serde_json::to_string(&json_routes).unwrap_or_else(|_| "[]".to_string());
    CString::new(json_str)
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Send standard Wake-on-LAN (WoL) Magic Packet (e.g. to wake PC or console)
#[no_mangle]
pub extern "C" fn mkt_send_wol(
    target_mac_cstr: *const c_char,
    broadcast_addr_cstr: *const c_char,
) -> i32 {
    if target_mac_cstr.is_null() {
        return -1;
    }

    let target_mac_str = match unsafe { CStr::from_ptr(target_mac_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let target_mac: MacAddr = match target_mac_str.parse() {
        Ok(m) => m,
        Err(_) => return -3,
    };

    let broadcast_addr = if !broadcast_addr_cstr.is_null() {
        match unsafe { CStr::from_ptr(broadcast_addr_cstr) }.to_str() {
            Ok(s) if !s.is_empty() => s,
            _ => "255.255.255.255:9",
        }
    } else {
        "255.255.255.255:9"
    };

    match send_wol_packet(&target_mac, broadcast_addr) {
        Ok(_) => 0,
        Err(_) => -4,
    }
}

/// Send PlayStation 5 Remote Play Wakeup Packet over UDP port 9302
#[no_mangle]
pub extern "C" fn mkt_send_ps5_wakeup(
    target_ip_cstr: *const c_char,
    user_credential_cstr: *const c_char,
) -> i32 {
    if target_ip_cstr.is_null() {
        return -1;
    }

    let target_ip = match unsafe { CStr::from_ptr(target_ip_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let user_cred = if !user_credential_cstr.is_null() {
        match unsafe { CStr::from_ptr(user_credential_cstr) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    } else {
        None
    };

    match send_ps5_wakeup_packet(target_ip, user_cred) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

/// Verify client EC-SRP5 authentication from PHP
#[no_mangle]
pub extern "C" fn mkt_srp_verify_client(
    username_cstr: *const c_char,
    password_cstr: *const c_char,
    client_pub_a: *const u8,
    client_m1: *const u8,
    out_server_m2: *mut u8,
    out_session_key: *mut u8,
) -> i32 {
    if username_cstr.is_null()
        || password_cstr.is_null()
        || client_pub_a.is_null()
        || client_m1.is_null()
        || out_server_m2.is_null()
        || out_session_key.is_null()
    {
        return -1;
    }

    let username = match unsafe { CStr::from_ptr(username_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let password = match unsafe { CStr::from_ptr(password_cstr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -3,
    };

    let mut pub_a = [0u8; 32];
    let mut m1 = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(client_pub_a, pub_a.as_mut_ptr(), 32);
        std::ptr::copy_nonoverlapping(client_m1, m1.as_mut_ptr(), 32);
    }

    let srp_server = SrpServerSession::new(username, password);
    match srp_server.verify_client_and_respond(&pub_a, &m1) {
        Ok((session_key, m2)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(m2.as_ptr(), out_server_m2, 32);
                std::ptr::copy_nonoverlapping(session_key.as_ptr(), out_session_key, 32);
            }
            0 // Success
        }
        Err(_) => 1, // Auth failed
    }
}

/// Spawns the background HTTPS relay server on TCP 443
#[no_mangle]
pub extern "C" fn mkt_start_https_relay(bind_addr_cstr: *const c_char) -> i32 {
    if bind_addr_cstr.is_null() {
        return -1;
    }

    let bind_addr = match unsafe { CStr::from_ptr(bind_addr_cstr) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -2,
    };

    let rt = get_runtime();
    rt.spawn(async move {
        match HttpsRelayServer::bind(&bind_addr).await {
            Ok(server) => {
                info!("PHP Module: Relay server bound to {}", bind_addr);
                loop {
                    if let Ok((_stream, addr)) = server.accept().await {
                        info!("Relay received connection from {}", addr);
                    }
                }
            }
            Err(e) => {
                info!("PHP Module: Failed to bind relay server: {}", e);
            }
        }
    });

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_abi_router_mac_filter_and_wakeup() {
        assert_eq!(mkt_version(), 1);

        let router = mkt_router_create();
        assert!(!router.is_null());

        let peer = CString::new("PS5-LivingRoom").unwrap();
        let endpoint = CString::new("192.168.1.100:443").unwrap();

        let res = mkt_route_add(router, 50, peer.as_ptr(), endpoint.as_ptr(), 1);
        assert_eq!(res, 0);

        let mac_filter = CString::new("00:D9:D1:AA:BB:CC").unwrap();
        let filter_res = mkt_route_set_mac_filter(router, 50, mac_filter.as_ptr());
        assert_eq!(filter_res, 0);

        let json_ptr = mkt_routes_list_json(router);
        assert!(!json_ptr.is_null());

        let json_str = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap();
        assert!(json_str.contains("PS5-LivingRoom"));
        assert!(json_str.contains("00:D9:D1:AA:BB:CC"));

        mkt_string_free(json_ptr);
        mkt_router_free(router);
    }
}
