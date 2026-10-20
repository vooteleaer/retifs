//! Who is asking: the gateway answers only its own user. On Linux the owner
//! of a localhost TCP connection is in `/proc/net/tcp{,6}` (the uid column of
//! the client's socket), so other users on the machine are refused. On
//! Windows the TCP table names the connection's process, and its token's user
//! SID must be ours. Processes of the same user could use the daemon's socket
//! (pipe) anyway.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![cfg_attr(windows, allow(unsafe_code))]

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

/// Windows: the process owning the client's end of the connection must run
/// as this user (same token user SID). Fails closed.
#[cfg(windows)]
pub fn is_own_user(peer: &SocketAddr, port: u16) -> bool {
    win::owner_pid(peer, port).is_some_and(win::same_user)
}

/// Elsewhere there is no cheap way to tell; the gateway listens on loopback only.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn is_own_user(_peer: &SocketAddr, _port: u16) -> bool {
    true
}

#[cfg(windows)]
mod win {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS},
        Networking::WinSock::{AF_INET, AF_INET6},
        Security::{EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    /// A port as the TCP table stores it: network order in the low 16 bits.
    fn port_of(dw: u32) -> u16 {
        u16::from_be(dw as u16)
    }

    fn table(af: u16) -> Option<Vec<u8>> {
        let mut size = 0u32;
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize];
            let ptr = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() };
            // SAFETY: buf has `size` bytes; the call writes at most that many and updates `size`.
            let rc = unsafe { GetExtendedTcpTable(ptr, &mut size, 0, af as u32, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
            if rc == 0 && !buf.is_empty() {
                return Some(buf);
            }
        }
        None
    }

    /// The process owning the TCP connection whose local end is `peer` and remote port `port`.
    pub fn owner_pid(peer: &SocketAddr, port: u16) -> Option<u32> {
        let ip = match peer.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let peer = SocketAddr::new(ip, peer.port());
        match ip {
            IpAddr::V4(_) => {
                let buf = table(AF_INET)?;
                let n = u32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
                let row = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                (0..n).find_map(|i| {
                    let at = 4 + i * row;
                    let bytes = buf.get(at..at + row)?;
                    // SAFETY: `bytes` is one whole row; read_unaligned copes with any alignment.
                    let r: MIB_TCPROW_OWNER_PID = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
                    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())), port_of(r.dwLocalPort));
                    (local == peer && port_of(r.dwRemotePort) == port).then_some(r.dwOwningPid)
                })
            }
            IpAddr::V6(_) => {
                let buf = table(AF_INET6)?;
                let n = u32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
                let row = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
                (0..n).find_map(|i| {
                    let at = 4 + i * row;
                    let bytes = buf.get(at..at + row)?;
                    // SAFETY: as above.
                    let r: MIB_TCP6ROW_OWNER_PID = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
                    let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port_of(r.dwLocalPort));
                    (local == peer && port_of(r.dwRemotePort) == port).then_some(r.dwOwningPid)
                })
            }
        }
    }

    /// The TOKEN_USER of a process (its buffer holds the SID).
    fn token_user(process: HANDLE) -> Option<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: plain Win32 calls on handles we own; buffers sized by the first call.
        unsafe {
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = len > 0 && GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) != 0;
            CloseHandle(token);
            ok.then_some(buf)
        }
    }

    /// Whether process `pid` runs as the same user as this one.
    pub fn same_user(pid: u32) -> bool {
        // SAFETY: the handle is checked and closed; SIDs point into buffers alive below.
        unsafe {
            let other = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if other.is_null() {
                return false; // e.g. another user's process: not ours to open
            }
            let theirs = token_user(other);
            CloseHandle(other);
            let (Some(theirs), Some(mine)) = (theirs, token_user(GetCurrentProcess())) else { return false };
            let a = std::ptr::read_unaligned(theirs.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let b = std::ptr::read_unaligned(mine.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            EqualSid(a, b) != 0
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn finds_this_process_as_the_owner_of_its_own_connection() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let _client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (_conn, peer) = listener.accept().unwrap();
            assert_eq!(super::owner_pid(&peer, port), Some(std::process::id()));
            assert!(super::super::is_own_user(&peer, port));
            assert_eq!(super::owner_pid(&"127.0.0.1:1".parse().unwrap(), port), None);
        }
    }
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
