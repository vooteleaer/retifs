//! Passing open files over the Unix socket (SCM_RIGHTS): a client hands the
//! daemon a descriptor instead of the file's bytes (ADR-0004, fd passing).
//! The daemon reads the file itself, so nothing is copied through the socket
//! and the client never holds the file in memory.

use std::{
    collections::VecDeque,
    fs::File,
    io,
    os::fd::{FromRawFd, RawFd},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::UnixStream;

/// Descriptors received on one connection, oldest first.
pub type FdQueue = Arc<Mutex<VecDeque<File>>>;

/// At most this many unclaimed descriptors are kept per connection; more are closed.
const MAX_QUEUED: usize = 4;

/// Sends `data` with descriptor `fd` attached. Returns the bytes sent (the
/// descriptor goes with the first of them; send the rest normally).
pub fn send_with_fd(sock: RawFd, data: &[u8], fd: RawFd) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    // SAFETY: the control buffer is sized by CMSG_SPACE for one int and 8-aligned;
    // every pointer handed to sendmsg lives until it returns.
    unsafe {
        let space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
        let mut control = vec![0u64; space.div_ceil(8)];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        libc::CMSG_DATA(c).cast::<libc::c_int>().write_unaligned(fd);
        let n = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}

/// Receives into `buf`; descriptors that come along are queued in `out`.
pub fn recv_with_fds(sock: RawFd, buf: &mut [u8], out: &FdQueue) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut control = [0u64; 16];
    // SAFETY: as above; descriptors read from SCM_RIGHTS are new and owned here.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let n = libc::recvmsg(sock, &mut msg, flags);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c).cast::<libc::c_int>();
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<libc::c_int>();
                let mut q = out.lock().unwrap();
                for i in 0..count {
                    let f = File::from_raw_fd(data.add(i).read_unaligned());
                    if q.len() < MAX_QUEUED {
                        q.push_back(f);
                    } // else dropped: closed
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok(n as usize)
    }
}

/// The daemon's side of a Unix socket connection: reads with `recvmsg`, so
/// descriptors sent with a request are kept (a plain read would close them).
pub struct FdStream {
    inner: UnixStream,
    pub fds: FdQueue,
}

impl FdStream {
    pub fn new(inner: UnixStream) -> Self {
        FdStream { inner, fds: Arc::new(Mutex::new(VecDeque::new())) }
    }
}

impl AsyncRead for FdStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        use std::os::fd::AsRawFd;
        let this = self.get_mut();
        loop {
            match this.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let fd = this.inner.as_raw_fd();
            let fds = this.fds.clone();
            let dst = buf.initialize_unfilled();
            match this.inner.try_io(Interest::READABLE, || recv_with_fds(fd, dst, &fds)) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for FdStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;

    #[test]
    fn a_descriptor_travels_with_the_bytes() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut f = tempfile_in_tmp();
        f.write_all(b"passed by descriptor").unwrap();
        f.rewind().unwrap();
        assert_eq!(send_with_fd(a.as_raw_fd(), b"frame", f.as_raw_fd()).unwrap(), 5);
        let q: FdQueue = Default::default();
        let mut buf = [0u8; 16];
        assert_eq!(recv_with_fds(b.as_raw_fd(), &mut buf, &q).unwrap(), 5);
        assert_eq!(&buf[..5], b"frame");
        let mut got = q.lock().unwrap().pop_front().expect("a descriptor");
        let mut s = String::new();
        got.read_to_string(&mut s).unwrap();
        assert_eq!(s, "passed by descriptor");
    }

    fn tempfile_in_tmp() -> File {
        let p = std::env::temp_dir().join(format!("retifs-fdpass-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        f
    }
}
