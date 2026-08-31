//! Python-exposed UDP socket helpers using quinn-udp.
//!
//! The Python side owns the socket and manages the event loop.
//! This module only provides the fast syscall wrappers:
//! - `recv()`: recvmmsg/recvmsg_x (batched) with automatic GRO splitting
//! - `send()`: sendmsg/sendmsg_x with automatic GSO coalescing
//!
//! On Linux:  recvmmsg + sendmsg with UDP_SEGMENT (kernel GRO/GSO)
//! On macOS:  recvmsg_x + sendmsg_x (Apple private batch APIs)

#[cfg(unix)]
use std::borrow::Cow;
#[cfg(unix)]
use std::io::IoSliceMut;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
#[cfg(unix)]
use std::os::unix::io::{BorrowedFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::sync::Mutex;

use pyo3::prelude::*;
#[cfg(unix)]
use pyo3::types::PyBytes;
use pyo3::types::{PyList, PyTuple};

#[cfg(unix)]
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, BATCH_SIZE};

/// Per-slot receive buffer size: 65536 bytes handles max GRO coalescing.
#[cfg(unix)]
const RECV_BUF_LEN: usize = 65536;

#[pyclass(name = "UdpSocketState")]
pub struct PyUdpSocketState {
    #[cfg(unix)]
    inner: quinn_udp::UdpSocketState,
    #[cfg(unix)]
    fd: OwnedFd,
    #[cfg(unix)]
    recv_buf: Mutex<Vec<u8>>,
    #[cfg(unix)]
    max_gso: usize,
    #[cfg(unix)]
    gro: usize,
}

#[pymethods]
impl PyUdpSocketState {
    /// Create a UdpSocketState from a file descriptor.
    ///
    /// The caller (Python transport) is responsible for socket creation,
    /// binding, and enabling GRO/GSO via setsockopt. This constructor
    /// only initialises the quinn-udp state needed for recv/send syscalls.
    #[new]
    fn new(fd: i64) -> PyResult<Self> {
        #[cfg(unix)]
        {
            let raw_fd = RawFd::try_from(fd).map_err(|_| {
                pyo3::exceptions::PyOverflowError::new_err("file descriptor does not fit in int")
            })?;
            if raw_fd < 0 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "file descriptor must be non-negative",
                ));
            }
            let borrowed = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let owned = borrowed
                .try_clone_to_owned()
                .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
            let sock_ref = UdpSockRef::from(&owned);

            let state = quinn_udp::UdpSocketState::new(sock_ref)
                .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;

            // Enable Apple's private sendmsg_x/recvmsg_x batch APIs when available.
            // These are resolved via dlsym at runtime; if the symbols are absent
            // the fast path is automatically disabled on first use.
            // The `fast-apple-datapath` feature of quinn-udp is always enabled in
            // Cargo.toml, so `set_apple_fast_path()` is compiled on Apple targets.
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos"
            ))]
            // SAFETY: quinn-udp resolves sendmsg_x / recvmsg_x via dlsym at
            // runtime and falls back gracefully if the symbols are not present.
            unsafe {
                state.set_apple_fast_path();
            }

            let max_gso = state.max_gso_segments();
            let gro = state.gro_segments();

            Ok(Self {
                inner: state,
                fd: owned,
                recv_buf: Mutex::new(vec![0u8; RECV_BUF_LEN * BATCH_SIZE]),
                max_gso,
                gro,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "UdpSocketState is only supported on Unix platforms",
            ))
        }
    }

    #[getter]
    fn max_gso_segments(&self) -> usize {
        #[cfg(unix)]
        {
            self.max_gso
        }
        #[cfg(not(unix))]
        {
            1
        }
    }

    #[getter]
    fn gro_segments(&self) -> usize {
        #[cfg(unix)]
        {
            self.gro
        }
        #[cfg(not(unix))]
        {
            1
        }
    }

    #[getter]
    fn may_fragment(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.may_fragment()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// Batch-receive datagrams via recvmmsg with GRO splitting.
    ///
    /// Returns ``list[tuple[bytes, addr]]``, preserving the source address
    /// from every receive slot for each datagram produced by GRO splitting.
    /// Returns an empty list when the socket would block.
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        #[cfg(unix)]
        {
            let mut buf = self.recv_buf.lock().map_err(|_| {
                pyo3::exceptions::PyOSError::new_err("UDP receive buffer lock poisoned")
            })?;
            let slot_count = buf.len() / RECV_BUF_LEN;
            let mut metas = vec![RecvMeta::default(); slot_count];

            let mut iovs: Vec<IoSliceMut<'_>> =
                buf.chunks_mut(RECV_BUF_LEN).map(IoSliceMut::new).collect();

            let sock_ref = UdpSockRef::from(&self.fd);

            let n = match self.inner.recv(sock_ref, &mut iovs, &mut metas) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(PyList::empty(py));
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                }
            };

            if n == 0 {
                return Ok(PyList::empty(py));
            }

            let datagrams = PyList::empty(py);
            for i in 0..n {
                let meta = &metas[i];
                let data = &iovs[i][..meta.len];
                if meta.stride > 0 && meta.len > meta.stride {
                    for chunk in data.chunks(meta.stride) {
                        append_received_datagram(py, &datagrams, chunk, meta.addr)?;
                    }
                } else {
                    append_received_datagram(py, &datagrams, data, meta.addr)?;
                }
            }

            Ok(datagrams)
        }
        #[cfg(not(unix))]
        {
            let _ = py;
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "recv is only supported on Unix platforms",
            ))
        }
    }

    /// Send datagrams with automatic GSO coalescing.
    ///
    /// Accepts a Python list of `bytes` objects and accesses their
    /// underlying buffers directly via `PyBytes::as_bytes()`.
    ///
    /// Returns the number of datagrams successfully sent.
    fn send<'py>(
        &self,
        _py: Python<'py>,
        datagrams: Bound<'py, PyList>,
        addr: &Bound<'py, PyTuple>,
    ) -> PyResult<usize> {
        let count = datagrams.len();
        if count == 0 {
            return Ok(0);
        }

        #[cfg(unix)]
        {
            let dest = socket_addr_from_py(addr)?;

            let mut sent = 0usize;

            // We keep the Bound<PyBytes> handles alive so the &[u8] borrows remain valid.
            let items: Vec<Bound<'py, PyBytes>> = datagrams
                .iter()
                .map(|item| item.cast_into::<PyBytes>().map_err(pyo3::PyErr::from))
                .collect::<PyResult<_>>()?;
            let slices: Vec<&[u8]> = items.iter().map(|b| b.as_bytes()).collect();

            if self.max_gso > 1 {
                let mut i = 0;
                while i < slices.len() {
                    let seg_size = slices[i].len();
                    let cap = 65000usize
                        .checked_div(seg_size)
                        .map_or(1, |cap| self.max_gso.min(cap).max(1));
                    let mut end = i + 1;

                    while end < slices.len() && end - i < cap {
                        let dlen = slices[end].len();
                        if dlen == 0 {
                            break;
                        } else if dlen == seg_size {
                            end += 1;
                        } else if dlen < seg_size {
                            end += 1;
                            break;
                        } else {
                            break;
                        }
                    }

                    let group_count = end - i;

                    let contents = coalesce_gso_group(&slices[i..end]);

                    let transmit = Transmit {
                        destination: dest,
                        ecn: None,
                        contents: contents.as_ref(),
                        segment_size: if group_count > 1 {
                            Some(seg_size)
                        } else {
                            None
                        },
                        src_ip: None,
                    };

                    let sock_ref = UdpSockRef::from(&self.fd);
                    match self.inner.try_send(sock_ref, &transmit) {
                        Ok(()) => sent += group_count,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                        }
                    }

                    i = end;
                }
            } else {
                // Non-GSO
                for s in &slices {
                    let transmit = Transmit {
                        destination: dest,
                        ecn: None,
                        contents: s,
                        segment_size: None,
                        src_ip: None,
                    };

                    let sock_ref = UdpSockRef::from(&self.fd);
                    match self.inner.try_send(sock_ref, &transmit) {
                        Ok(()) => sent += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                        }
                    }
                }
            }

            Ok(sent)
        }
        #[cfg(not(unix))]
        {
            let _ = (_py, datagrams, addr);
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "send is only supported on Unix platforms",
            ))
        }
    }
}

#[cfg(unix)]
fn socket_addr_to_py<'py>(py: Python<'py>, addr: SocketAddr) -> PyResult<Bound<'py, PyTuple>> {
    match addr {
        SocketAddr::V4(addr) => PyTuple::new(
            py,
            &[
                addr.ip().to_string().into_pyobject(py)?.into_any(),
                addr.port().into_pyobject(py)?.into_any(),
            ],
        ),
        SocketAddr::V6(addr) => PyTuple::new(
            py,
            &[
                addr.ip().to_string().into_pyobject(py)?.into_any(),
                addr.port().into_pyobject(py)?.into_any(),
                addr.flowinfo().into_pyobject(py)?.into_any(),
                addr.scope_id().into_pyobject(py)?.into_any(),
            ],
        ),
    }
}

#[cfg(unix)]
fn append_received_datagram<'py>(
    py: Python<'py>,
    datagrams: &Bound<'py, PyList>,
    data: &[u8],
    addr: SocketAddr,
) -> PyResult<()> {
    let data = PyBytes::new(py, data);
    let addr = socket_addr_to_py(py, addr)?;
    datagrams.append(PyTuple::new(py, [data.as_any(), addr.as_any()])?)
}

#[cfg(unix)]
fn socket_addr_from_py(addr: &Bound<'_, PyTuple>) -> PyResult<SocketAddr> {
    let ip_text: String = addr.get_item(0)?.extract()?;
    let port: u16 = addr.get_item(1)?.extract()?;
    let ip: IpAddr = ip_text.parse().map_err(|e: std::net::AddrParseError| {
        pyo3::exceptions::PyValueError::new_err(e.to_string())
    })?;

    match addr.len() {
        2 => Ok(SocketAddr::new(ip, port)),
        4 => {
            let IpAddr::V6(ip) = ip else {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "flowinfo and scope_id require an IPv6 address",
                ));
            };
            let flowinfo: u32 = addr.get_item(2)?.extract()?;
            let scope_id: u32 = addr.get_item(3)?.extract()?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip, port, flowinfo, scope_id,
            )))
        }
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "address must be a 2-tuple or IPv6 4-tuple",
        )),
    }
}

#[cfg(unix)]
fn coalesce_gso_group<'a>(group: &[&'a [u8]]) -> Cow<'a, [u8]> {
    if group.len() == 1 {
        return Cow::Borrowed(group[0]);
    }
    let total_len = group.iter().map(|slice| slice.len()).sum();
    let mut contents = Vec::with_capacity(total_len);
    for slice in group {
        contents.extend_from_slice(slice);
    }
    Cow::Owned(contents)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn single_gso_group_borrows_original_datagram() {
        let datagram = b"one packet";
        let contents = coalesce_gso_group(&[datagram.as_slice()]);

        assert!(matches!(contents, Cow::Borrowed(_)));
        assert_eq!(contents.as_ptr(), datagram.as_ptr());
    }

    #[test]
    fn multiple_gso_segments_are_coalesced() {
        let contents = coalesce_gso_group(&[b"one".as_slice(), b"two".as_slice()]);

        assert!(matches!(contents, Cow::Owned(_)));
        assert_eq!(contents.as_ref(), b"onetwo");
    }
}
