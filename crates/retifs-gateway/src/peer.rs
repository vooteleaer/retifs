//! Who is asking: the gateway answers only its own user. On Linux the owner
//! of a localhost TCP connection is in `/proc/net/tcp{,6}` (the uid column of
//! the client's socket), so other users on the machine are refused. Processes
//! of the same user could use the daemon's socket anyway.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, SocketAddr};

/// Whether the connection from `peer` to our `port` belongs to this user.
/// Fails closed: an unknown owner is refused.
#[cfg(target_os = "linux")]
pub fn is_own_user(peer: &SocketAddr, port: u16) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata("/proc/self").map(|m| m.uid()) else {
        return false;
    };
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .find_map(|table| owner(&table, peer, port))
        == Some(me)
}

/// Elsewhere there is no cheap way to tell; the gateway listens on loopback only.
#[cfg(not(target_os = "linux"))]
pub fn is_own_user(_peer: &SocketAddr, _port: u16) -> bool {
    true
}

/// The uid of the socket whose local end is `peer` and remote port is `port`,
/// from a `/proc/net/tcp` or `tcp6` table.
pub fn owner(table: &str, peer: &SocketAddr, port: u16) -> Option<u32> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            return None;
        }
        let local = parse_addr(cols[1])?;
        let remote = parse_addr(cols[2])?;
        (same_addr(&local, peer) && remote.port() == port)
            .then(|| cols[7].parse().ok())
            .flatten()
    })
}

/// `0100007F:1F64` (IPv4) or 32 hex digits + port (IPv6); each 32-bit word is
/// in host byte order, which is little-endian on every target we build for.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words: Vec<u32> = (0..ip.len() / 8)
        .map(|i| u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let ip = match bytes.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Same address, treating IPv4 and its IPv4-mapped IPv6 form as one.
fn same_addr(a: &SocketAddr, b: &SocketAddr) -> bool {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    a.port() == b.port() && canon(a.ip()) == canon(b.ip())
}

/// Requests other websites make in the background (images, scripts, fetches)
/// are refused before any lookup: they could probe which namespaces and files
/// exist, or make the node fetch content. Following a link (navigation) is fine.
pub fn cross_site_subresource(sec_fetch_site: Option<&str>, sec_fetch_mode: Option<&str>) -> bool {
    sec_fetch_site == Some("cross-site") && sec_fetch_mode != Some("navigate")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2224 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D431 0100007F:2224 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:2224 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:B0F2 00000000000000000000000001000000:2224 01 00000000:00000000 00:00000000 00000000  1002        0 4 1 0000000000000000 20 4 30 10 -1
";

    #[test]
    fn finds_the_clients_socket_not_the_servers() {
        // The client's end (port 0xD431 = 54321) is owned by uid 1001; the
        // gateway's own end of the same connection (uid 1000) must not match.
        let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        assert_eq!(owner(TCP, &peer, 0x2224), Some(1001));
        assert_eq!(owner(TCP, &peer, 9999), None);
        assert_eq!(owner(TCP, &"127.0.0.1:1".parse().unwrap(), 0x2224), None);
    }

    #[test]
    fn ipv6_and_mapped_addresses() {
        assert_eq!(
            owner(TCP6, &"[::1]:45298".parse().unwrap(), 0x2224),
            Some(1002)
        );
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:54321".parse().unwrap();
        assert_eq!(owner(TCP, &mapped, 0x2224), Some(1001));
    }

    #[test]
    fn only_cross_site_background_requests_are_refused() {
        assert!(cross_site_subresource(Some("cross-site"), Some("no-cors")));
        assert!(cross_site_subresource(Some("cross-site"), Some("cors")));
        assert!(cross_site_subresource(Some("cross-site"), None));
        assert!(!cross_site_subresource(
            Some("cross-site"),
            Some("navigate")
        ));
        assert!(!cross_site_subresource(
            Some("same-origin"),
            Some("no-cors")
        ));
        assert!(!cross_site_subresource(Some("none"), Some("navigate")));
        assert!(!cross_site_subresource(None, None)); // curl, older browsers
    }
}
